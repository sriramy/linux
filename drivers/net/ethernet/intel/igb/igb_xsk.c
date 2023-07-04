// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. */

#include <linux/bpf_trace.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp.h>

#include "e1000_hw.h"
#include "igb.h"

struct xsk_buff_pool *igb_xsk_pool(struct igb_adapter *adapter,
				   struct igb_ring *ring)
{
	int qid = ring->queue_index;

	if (!igb_xdp_is_enabled(adapter) ||
	    !test_bit(IGB_RING_FLAG_AF_XDP_ZC, &ring->flags))
		return NULL;

	return xsk_get_pool_from_qid(adapter->netdev, qid);
}

static int igb_xsk_pool_enable(struct igb_adapter *adapter,
			       struct xsk_buff_pool *pool,
			       u16 qid)
{
	struct net_device *netdev = adapter->netdev;
	struct igb_ring *tx_ring, *rx_ring;
	bool if_running;
	int err;

	if (qid >= adapter->num_rx_queues)
		return -EINVAL;

	if (qid >= netdev->real_num_rx_queues ||
	    qid >= netdev->real_num_tx_queues)
		return -EINVAL;

	err = xsk_pool_dma_map(pool, &adapter->pdev->dev, IGB_RX_DMA_ATTR);
	if (err)
		return err;

	tx_ring = adapter->tx_ring[qid];
	rx_ring = adapter->rx_ring[qid];
	if_running = netif_running(adapter->netdev) && igb_xdp_is_enabled(adapter);
	if (if_running)
		igb_txrx_ring_disable(adapter, qid);

	set_bit(IGB_RING_FLAG_AF_XDP_ZC, &tx_ring->flags);
	set_bit(IGB_RING_FLAG_AF_XDP_ZC, &rx_ring->flags);

	if (if_running) {
		igb_txrx_ring_enable(adapter, qid);

		/* Kick start the NAPI context so that receiving will start */
		err = igb_xsk_wakeup(adapter->netdev, qid, XDP_WAKEUP_RX);
		if (err) {
			clear_bit(IGB_RING_FLAG_AF_XDP_ZC, &tx_ring->flags);
			clear_bit(IGB_RING_FLAG_AF_XDP_ZC, &rx_ring->flags);
			xsk_pool_dma_unmap(pool, IGB_RX_DMA_ATTR);
			return err;
		}
	}

	return 0;
}

static int igb_xsk_pool_disable(struct igb_adapter *adapter, u16 qid)
{
	struct igb_ring *tx_ring, *rx_ring;
	struct xsk_buff_pool *pool;
	bool if_running;

	pool = xsk_get_pool_from_qid(adapter->netdev, qid);
	if (!pool)
		return -EINVAL;

	tx_ring = adapter->tx_ring[qid];
	rx_ring = adapter->rx_ring[qid];
	if_running = netif_running(adapter->netdev) && igb_xdp_is_enabled(adapter);
	if (if_running)
		igb_txrx_ring_disable(adapter, qid);

	xsk_pool_dma_unmap(pool, IGB_RX_DMA_ATTR);
	clear_bit(IGB_RING_FLAG_AF_XDP_ZC, &tx_ring->flags);
	clear_bit(IGB_RING_FLAG_AF_XDP_ZC, &rx_ring->flags);

	if (if_running)
		igb_txrx_ring_enable(adapter, qid);

	return 0;
}

int igb_xsk_pool_setup(struct igb_adapter *adapter,
		       struct xsk_buff_pool *pool,
		       u16 qid)
{
	return pool ? igb_xsk_pool_enable(adapter, pool, qid) :
		igb_xsk_pool_disable(adapter, qid);
}

bool igb_alloc_rx_buffers_zc(struct igb_ring *rx_ring, u16 count)
{
	union e1000_adv_rx_desc *rx_desc;
	struct igb_rx_buffer *buffer_info;
	u16 i = rx_ring->next_to_use;
	dma_addr_t dma;
	bool ok = true;

	/* nothing to do */
	if (!count)
		return true;

	rx_desc = IGB_RX_DESC(rx_ring, i);
	buffer_info = &rx_ring->rx_buffer_info[i];
	i -= rx_ring->count;

	do {
		buffer_info->xdp = xsk_buff_alloc(rx_ring->xsk_pool);
		if (!buffer_info->xdp) {
			ok = false;
			break;
		}

		dma = xsk_buff_xdp_get_dma(buffer_info->xdp);

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
		rx_desc->read.pkt_addr = cpu_to_le64(dma);

		rx_desc++;
		buffer_info++;
		i++;
		if (unlikely(!i)) {
			rx_desc = IGB_RX_DESC(rx_ring, 0);
			buffer_info = rx_ring->rx_buffer_info;
			i -= rx_ring->count;
		}

		/* clear the length for the next_to_use descriptor */
		rx_desc->wb.upper.length = 0;

		count--;
	} while (count);

	i += rx_ring->count;

	if (rx_ring->next_to_use != i) {
		rx_ring->next_to_use = i;

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel(i, rx_ring->tail);
	}

	return ok;
}

static struct sk_buff *igb_construct_skb_zc(struct igb_ring *rx_ring,
					    struct xdp_buff *xdp,
					    ktime_t timestamp)
{
	unsigned int totalsize = xdp->data_end - xdp->data_meta;
	unsigned int metasize = xdp->data - xdp->data_meta;
	struct sk_buff *skb;

	net_prefetch(xdp->data_meta);

	/* allocate a skb to store the frags */
	skb = __napi_alloc_skb(&rx_ring->q_vector->napi, totalsize,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	if (timestamp)
		skb_hwtstamps(skb)->hwtstamp = timestamp;

	memcpy(__skb_put(skb, totalsize), xdp->data_meta,
	       ALIGN(totalsize, sizeof(long)));

	if (metasize) {
		skb_metadata_set(skb, metasize);
		__skb_pull(skb, metasize);
	}

	return skb;
}

static void igb_update_ntc(struct igb_ring *rx_ring)
{
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	prefetch(IGB_RX_DESC(rx_ring, ntc));
}

int igb_clean_rx_irq_zc(struct igb_q_vector *q_vector, const int budget)
{
	struct igb_adapter *adapter = q_vector->adapter;
	struct igb_ring *rx_ring = q_vector->rx.ring;
	struct sk_buff *skb;
	int cpu = smp_processor_id();
	struct netdev_queue *nq;
	unsigned int total_bytes = 0, total_packets = 0;
	u16 cleaned_count = igb_desc_unused(rx_ring);
	unsigned int xdp_xmit = 0;
	bool failure = false;

	while (likely(total_packets < budget)) {
		union e1000_adv_rx_desc *rx_desc;
		struct igb_rx_buffer *rx_buffer;
		ktime_t timestamp = 0;
		unsigned int size;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IGB_RX_BUFFER_WRITE) {
			igb_alloc_rx_buffers_zc(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = IGB_RX_DESC(rx_ring, rx_ring->next_to_clean);
		size = le16_to_cpu(rx_desc->wb.upper.length);
		if (!size)
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		dma_rmb();

		rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
		rx_buffer->xdp->data_end = rx_buffer->xdp->data + size;
		xsk_buff_dma_sync_for_cpu(rx_buffer->xdp, rx_ring->xsk_pool);

		/* pull rx packet timestamp if available and valid */
		if (igb_test_staterr(rx_desc, E1000_RXDADV_STAT_TSIP)) {
			int ts_hdr_len;

			ts_hdr_len = igb_ptp_rx_pktstamp(rx_ring->q_vector,
							 rx_buffer->xdp->data,
							 &timestamp);

			rx_buffer->xdp->data += ts_hdr_len;
			rx_buffer->xdp->data_meta += ts_hdr_len;
			size -= ts_hdr_len;
		}

		skb = igb_run_xdp(adapter, rx_ring, rx_buffer->xdp);

		if (IS_ERR(skb)) {
			unsigned int xdp_res = -PTR_ERR(skb);

			if (likely(xdp_res & (IGB_XDP_TX | IGB_XDP_REDIR))) {
				xdp_xmit |= xdp_res;
			} else if (xdp_res == IGB_XDP_EXIT) {
				failure = true;
				break;
			} else if (xdp_res == IGB_XDP_CONSUMED) {
				xsk_buff_free(rx_buffer->xdp);
			}

			total_packets++;
			total_bytes += size;

			rx_buffer->xdp = NULL;
			cleaned_count++;
			igb_update_ntc(rx_ring);
			continue;
		}

		skb = igb_construct_skb_zc(rx_ring, rx_buffer->xdp, timestamp);

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->rx_stats.alloc_failed++;
			break;
		}

		xsk_buff_free(rx_buffer->xdp);
		rx_buffer->xdp = NULL;
		cleaned_count++;
		igb_update_ntc(rx_ring);

		if (eth_skb_pad(skb))
			continue;

		/* probably a little skewed due to removing CRC */
		total_bytes += skb->len;

		/* populate checksum, timestamp, VLAN, and protocol */
		igb_process_skb_fields(rx_ring, rx_desc, skb);

		napi_gro_receive(&q_vector->napi, skb);

		/* reset skb pointer */
		skb = NULL;

		/* update budget accounting */
		total_packets++;
	}

	if (xdp_xmit & IGB_XDP_REDIR)
		xdp_do_flush();

	if (xdp_xmit & IGB_XDP_TX) {
		struct igb_ring *tx_ring = igb_xdp_tx_queue_mapping(adapter);

		nq = txring_txq(tx_ring);
		__netif_tx_lock(nq, cpu);
		igb_xdp_ring_update_tail(tx_ring);
		__netif_tx_unlock(nq);
	}

	u64_stats_update_begin(&rx_ring->rx_syncp);
	rx_ring->rx_stats.packets += total_packets;
	rx_ring->rx_stats.bytes += total_bytes;
	u64_stats_update_end(&rx_ring->rx_syncp);
	q_vector->rx.total_packets += total_packets;
	q_vector->rx.total_bytes += total_bytes;

	if (cleaned_count)
		igb_alloc_rx_buffers_zc(rx_ring, cleaned_count);

	if (xsk_uses_need_wakeup(rx_ring->xsk_pool)) {
		if (failure || rx_ring->next_to_clean == rx_ring->next_to_use)
			xsk_set_rx_need_wakeup(rx_ring->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_pool);

		return (int)total_packets;
	}
	return failure ? budget : (int)total_packets;
}

bool igb_xmit_zc(struct igb_ring *tx_ring, unsigned int budget)
{
	struct xsk_buff_pool *pool = tx_ring->xsk_pool;
	union e1000_adv_tx_desc *tx_desc = NULL;
	struct igb_tx_buffer *tx_bi;
	bool work_done = true;
	struct xdp_desc desc;
	dma_addr_t dma;
	u32 cmd_type;

	while (budget-- > 0) {
		if (unlikely(!igb_desc_unused(tx_ring))) {
			work_done = false;
			break;
		}

		if (!netif_carrier_ok(tx_ring->netdev))
			break;

		if (!xsk_tx_peek_desc(pool, &desc))
			break;

		dma = xsk_buff_raw_get_dma(pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(pool, dma, desc.len);

		tx_bi = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
		tx_bi->bytecount = desc.len;
		tx_bi->type = IGB_TYPE_XSK;
		tx_bi->xdpf = NULL;
		tx_bi->gso_segs = 1;

		tx_desc = IGB_TX_DESC(tx_ring, tx_ring->next_to_use);
		tx_desc->read.buffer_addr = cpu_to_le64(dma);

		/* put descriptor type bits */
		cmd_type = E1000_ADVTXD_DTYP_DATA | E1000_ADVTXD_DCMD_DEXT |
			   E1000_ADVTXD_DCMD_IFCS;

		cmd_type |= desc.len | IGB_TXD_DCMD;
		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
		tx_desc->read.olinfo_status = 0;

		tx_ring->next_to_use++;
		if (tx_ring->next_to_use == tx_ring->count)
			tx_ring->next_to_use = 0;
	}

	if (tx_desc) {
		igb_xdp_ring_update_tail(tx_ring);
		xsk_tx_release(pool);
	}

	return !!budget && work_done;
}

int igb_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags)
{
	struct igb_adapter *adapter = netdev_priv(dev);
	struct igb_ring *ring;
	struct e1000_hw *hw = &adapter->hw;
	u32 eics = 0;

	if (test_bit(__IGB_DOWN, &adapter->state))
		return -ENETDOWN;

	if (!igb_xdp_is_enabled(adapter))
		return -EINVAL;

	if (qid >= adapter->num_tx_queues)
		return -EINVAL;

	ring = adapter->tx_ring[qid];

	if (test_bit(IGB_RING_FLAG_TX_DISABLED, &ring->flags))
		return -ENETDOWN;

	if (!ring->xsk_pool)
		return -EINVAL;

	if (!napi_if_scheduled_mark_missed(&ring->q_vector->napi)) {
		/* Cause software interrupt to ensure Rx ring is cleaned */
		if (adapter->flags & IGB_FLAG_HAS_MSIX) {
			eics |= ring->q_vector->eims_value;
			wr32(E1000_EICS, eics);
		} else {
			wr32(E1000_ICS, E1000_ICS_RXDMT0);
		}
	}

	return 0;
}
