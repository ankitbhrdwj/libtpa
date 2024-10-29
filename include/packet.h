/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
 * Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>
 */
#ifndef _PACKET_H_
#define _PACKET_H_

#include <sys/queue.h>

#include <rte_mbuf.h>

#include "lib/utils.h"
#include "tcp.h"
#include "cfg.h"
#include "flex_fifo.h"
#include "dpdk_compat.h"

/*
 * 64k/1448 ~= 45
 *
 * TODO: we should obey nb_seg_max/nb_mtu_seg_max
 */
#define PKT_MAX_CHAIN			45

#define PKT_FLAG_RETRANSMIT		(1u<<0)
#define PKT_FLAG_HAS_TS_OPT		(1u<<1)
#define PKT_FLAG_MEASURE_READ_LATENCY	(1u<<2)
#define PKT_FLAG_IS_IPV6		(1u<<3)
#define PKT_FLAG_VERIFY_CUT		(1u<<4)
#define PKT_FLAG_STALE_NEIGH		(1u<<5)

struct packet {
	struct rte_mbuf mbuf;

	uint16_t src_port;
	uint16_t dst_port;

	uint16_t flags;
	uint8_t  wid;
	uint8_t l2_off;
	uint8_t l3_off;
	uint8_t l4_off;

	/*
	 * The tcp payload offset; unlike other offsets, it's not fixed.
	 * It may vary as we do packet cut.
	 */
	uint16_t l5_off;
	uint16_t l5_len;
	uint8_t hdr_len;
	int8_t nr_read_seg;

	/*
	 * If there is a pkt chain,
	 * - TCP_SEG(head)->seq points to the first valid seq, which may
	 *   point to a seq in next pkt in the chain (after HEAD cut).
	 *
	 * - TCP_SEG(head)->len represents the TCP payload len of the
	 *   whole packet chain, where TCP_SEG(pkt)->l5_len represents
	 *   the acutal TCP payload for each TCP segment.
	 */
	struct {
		uint32_t seq;
		uint32_t ack;
		union {
			struct {
				uint32_t ts_val;
				uint32_t ts_ecr;
			};
			uint64_t ts_raw;
		};
		uint16_t wnd;
		uint16_t len;
		uint8_t  opt_len;
		uint8_t  flags;
	} __attribute__((packed)) tcp;

	uint16_t port_id;

	union {
		struct packet *tail;	/* for merge stage */
		struct packet *to_read; /* for read stage */
	};
	uint64_t ts_us;

	struct tcp_sock *tsock;
	union {
		TAILQ_ENTRY(packet) node; /* for ooo only so far */
		struct flex_fifo_node neigh_node;
	};

	struct {
		uint64_t start;
		uint64_t submit;
		uint64_t drain;
	} read_tsc;
} __rte_cache_aligned;

TAILQ_HEAD(packet_list, packet);

/* XXX: we support 2 NUMA at most */
#define TPA_MAX_NUMA			2
#define preferred_mempool(p)		((p)->pool[tpa_cfg.preferred_numa])
#define backup_mempool(p)		((p)->pool[!tpa_cfg.preferred_numa])

struct packet_pool {
	struct rte_mempool *pool[TPA_MAX_NUMA];
};

#define TCP_SEG(pkt)		(&((pkt)->tcp))
#define has_flag_syn(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_SYN) != 0)
#define has_flag_rst(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_RST) != 0)
#define has_flag_ack(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_ACK) != 0)
#define has_flag_psh(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_PSH) != 0)
#define has_flag_fin(pkt)	((TCP_SEG(pkt)->flags & TCP_FLAG_FIN) != 0)

/*
 * note that it points to mbuf->mbuf_addr directly, instead of the addr with
 * mbuf->data_off.
 */
static inline uint8_t *packet_data(struct packet *pkt)
{
	return pkt->mbuf.buf_addr;
}

static inline struct rte_ether_hdr *packet_eth_hdr(struct packet *pkt)
{
	return (struct rte_ether_hdr *)(packet_data(pkt) + pkt->l2_off);
}

static inline struct rte_ipv4_hdr *packet_ip_hdr(struct packet *pkt)
{
	return (struct rte_ipv4_hdr *)(packet_data(pkt) + pkt->l3_off);
}

static inline struct rte_ipv6_hdr *packet_ip6_hdr(struct packet *pkt)
{
	return (struct rte_ipv6_hdr *)(packet_data(pkt) + pkt->l3_off);
}

static inline int ip_is_frag(uint32_t frag_off)
{
	return (frag_off & htons(RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) != 0;
}

static inline struct rte_tcp_hdr *packet_tcp_hdr(struct packet *pkt)
{
	return (struct rte_tcp_hdr *)(packet_data(pkt) + pkt->l4_off);
}

static inline void *tcp_payload_addr(struct packet *pkt)
{
	return packet_data(pkt) + pkt->l5_off;
}

static inline uint64_t tcp_payload_phys_addr(struct packet *pkt)
{
	return pkt->mbuf.buf_iova + pkt->l5_off;
}

/*
 * A more lightweight external buf attach for zero copy write implementation.
 */
static inline void packet_attach_extbuf(struct packet *pkt, void *virt_addr,
					uint64_t phys_addr, uint16_t data_len)
{
	pkt->mbuf.buf_addr = virt_addr;
	pkt->mbuf.buf_iova = phys_addr;
	pkt->mbuf.pkt_len  = data_len;
	pkt->mbuf.data_len = data_len;
	pkt->mbuf.data_off = 0;
}

static inline void packet_init(struct packet *pkt)
{
	pkt->flags = 0;
	pkt->hdr_len = 0;

	TCP_SEG(pkt)->flags = 0;
	TCP_SEG(pkt)->len = 0;

	FLEX_FIFO_NODE_INIT(&pkt->neigh_node);
}

static inline struct rte_mempool *packet_pool_get_mempool(struct packet_pool *pool)
{
	return preferred_mempool(pool) ? preferred_mempool(pool) : backup_mempool(pool);
}

static inline struct packet *do_packet_alloc(struct rte_mempool *mempool)
{
	struct packet *pkt;

	if (unlikely(mempool == NULL))
		return NULL;

	pkt = (struct packet *)rte_pktmbuf_alloc(mempool);
	if (likely(pkt != NULL))
		packet_init(pkt);

	return pkt;
}

static inline struct packet *packet_alloc(struct packet_pool *pool)
{
	struct packet *pkt;

	pkt = do_packet_alloc(preferred_mempool(pool));
	if (unlikely(pkt == NULL))
		pkt = do_packet_alloc(backup_mempool(pool));

	return pkt;
}

static inline void packet_free(struct packet *pkt)
{
	rte_pktmbuf_free(&pkt->mbuf);
}

static inline void packet_free_batch(struct packet **pkts, int nr_pkt)
{
	int i;

	for (i = 0; i < nr_pkt; i++)
		packet_free(pkts[i]);
}

#define CUT_HEAD	1
#define CUT_TAIL	0

static inline void tcp_packet_cut_head(struct packet *head, int size)
{
	struct packet *pkt = head->to_read;

	TCP_SEG(head)->seq += size;

	while (pkt && size >= pkt->l5_len) {
		size -= pkt->l5_len;
		pkt = (struct packet *)(pkt->mbuf.next);
		head->nr_read_seg -= 1;
	}

	if (size) {
		pkt->l5_len -= size;
		pkt->l5_off += size;
	}

	head->to_read = pkt;
}

static inline void tcp_packet_cut_tail(struct packet *head, int size)
{
	struct packet *pkt = head->to_read;
	uint16_t nr_read_seg = 0;

	size = TCP_SEG(head)->len - size;
	while (pkt && size >= pkt->l5_len) {
		size -= pkt->l5_len;
		pkt = (struct packet *)(pkt->mbuf.next);
		nr_read_seg += 1;
	}

	if (size) {
		pkt->l5_len = size;
		nr_read_seg += 1;
	}

	head->nr_read_seg = nr_read_seg;
}

static inline void tcp_packet_cut_verify(struct packet *pkt)
{
	uint16_t size = TCP_SEG(pkt)->len;
	uint16_t nr_seg = pkt->nr_read_seg;

	pkt = pkt->to_read;
	while (size) {
		size -= pkt->l5_len;
		pkt = (struct packet *)(pkt->mbuf.next);
		nr_seg -= 1;
	}

	assert(nr_seg == 0);
}

static inline void tcp_packet_cut(struct packet *pkt, uint32_t size, int dir)
{
	debug_assert(TCP_SEG(pkt)->len >= size);

	if (dir == CUT_HEAD)
		tcp_packet_cut_head(pkt, size);
	else
		tcp_packet_cut_tail(pkt, size);

	TCP_SEG(pkt)->len -= size;


	/*
	 * XXX: normally, we should introduce a debug macro and only
	 * enable it when such macro is defined. However, it's not
	 * friendly for unit purpose: we wish to always do strict
	 * verification on unit test. Therefore, a hack is made here.
	 */
	if (unlikely(pkt->flags & PKT_FLAG_VERIFY_CUT))
		tcp_packet_cut_verify(pkt);
}

static inline void packet_chain(struct packet *head, struct packet *pkt)
{
	head->mbuf.nb_segs += 1;
	head->mbuf.pkt_len += pkt->mbuf.pkt_len;
	head->tail->mbuf.next = &pkt->mbuf;

	TCP_SEG(head)->len += pkt->l5_len;
	head->nr_read_seg += 1;
	head->tail = pkt;
}

int parse_tcp_opts(struct tcp_opts *opts, struct packet *pkt);
int verify_csum(struct packet *pkt);

/*
#define ETHERNET_HEADER_LEN 14
#define IPV4_HEADER_LEN 20
#define TCP_HEADER_LEN 20

static void print_ethernet_header(const uint8_t *packet) {
    printf("Ethernet Header:\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    printf("EtherType: 0x%02x%02x\n", packet[12], packet[13]);
}

static void print_ipv4_header(const uint8_t *packet) {
    printf("\nIPv4 Header:\n");
    printf("Version: %d\n", (packet[0] >> 4));
    printf("Header Length: %d bytes\n", (packet[0] & 0x0F) * 4);
    printf("Total Length: %d\n", (packet[2] << 8) | packet[3]);
    printf("Protocol: %d\n", packet[9]);
    printf("Source IP: %d.%d.%d.%d\n",
           packet[12], packet[13], packet[14], packet[15]);
    printf("Destination IP: %d.%d.%d.%d\n",
           packet[16], packet[17], packet[18], packet[19]);
}

static inline void print_tcp_flags(uint8_t flags) {
    printf("\nTCP Flags:\n");
    if (flags & 0x01) printf("FIN ");
    if (flags & 0x02) printf("SYN ");
    if (flags & 0x04) printf("RST ");
    if (flags & 0x08) printf("PSH ");
    if (flags & 0x10) printf("ACK ");
    if (flags & 0x20) printf("URG ");
    printf("\n");
}

static void print_tcp_header(const uint8_t *packet) {
    printf("\nTCP Header:\n");
    printf("Source Port: %d\n", (packet[0] << 8) | packet[1]);
    printf("Destination Port: %d\n", (packet[2] << 8) | packet[3]);
    printf("Sequence Number: %u\n", (packet[4] << 24) | (packet[5] << 16) | (packet[6] << 8) | packet[7]);
    printf("Acknowledgment Number: %u\n", (packet[8] << 24) | (packet[9] << 16) | (packet[10] << 8) | packet[11]);
    printf("Data Offset: %d bytes\n", (packet[12] >> 4) * 4);

    uint8_t flags = packet[13] & 0x3F;  // TCP flags are the lower 6 bits of the 13th byte
    print_tcp_flags(flags);
}

static void forward_packet(const uint8_t *packet, size_t length) {
    if (length < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN) {
        printf("Packet is too short to process!\n");
        return;
    }
    
    // Process Ethernet Header
    print_ethernet_header(packet);
    
    // Process IPv4 Header
    print_ipv4_header(packet + ETHERNET_HEADER_LEN);
    
    // Process TCP Header
    print_tcp_header(packet + ETHERNET_HEADER_LEN + IPV4_HEADER_LEN);
    
    // Additional forwarding logic or packet processing can be added here
    printf("\nPacket forwarding...\n");
}*/

#define IP4_HDR_LEN(ip)		((ip->version_ihl & 0xf) << 2)
/*
 * XXX: we probably could make some spaces to store bad pkts (for
 *      later analysis (if needed)
 */
static inline int parse_tcp_packet(struct packet *pkt)
{
	struct rte_mbuf *m = &pkt->mbuf;
	uint64_t csum_flags;
	struct rte_tcp_hdr *th;
	uint32_t ip_payload_len;
	uint16_t tcp_hdr_len;
	int err;

	debug_assert(pkt->mbuf.data_off <= 128);
	pkt->l2_off = pkt->mbuf.data_off;
	pkt->l3_off = pkt->l2_off + sizeof(struct rte_ether_hdr);
	//forward_packet(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len);

	if ((m->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP)) ==
			      (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP)) {
		struct rte_ipv4_hdr *ip = packet_ip_hdr(pkt);

		/* TODO: handle ip frags */
		if (unlikely(ip_is_frag(ip->fragment_offset)))
			return -PKT_IP_FRAG;

		csum_flags = PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD;
		ip_payload_len = ntohs(ip->total_length) - IP4_HDR_LEN(ip);
		pkt->l4_off = pkt->l3_off + IP4_HDR_LEN(ip);
	} else if ((m->packet_type & (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP)) ==
				     (RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP)) {
		struct rte_ipv6_hdr *ip = packet_ip6_hdr(pkt);

		if (unlikely(ip->proto != IPPROTO_TCP))
			return -ERR_PKT_HAS_IPV6_OPT;

		csum_flags = PKT_RX_L4_CKSUM_GOOD;
		ip_payload_len = ntohs(ip->payload_len);
		pkt->l4_off = pkt->l3_off + sizeof(struct rte_ipv6_hdr);
		pkt->flags |= PKT_FLAG_IS_IPV6;
	} else {
		return -ERR_PKT_NOT_TCP;
	}

	if ((m->ol_flags & csum_flags) != csum_flags) {
		err = 0; //verify_csum(pkt);
		if (err)
			return err;
	}

	th = packet_tcp_hdr(pkt);
	tcp_hdr_len = (th->data_off >> 4) << 2;
	pkt->l5_off = pkt->l4_off + tcp_hdr_len;
	pkt->hdr_len = pkt->l5_off - pkt->l2_off;
	if (unlikely(m->pkt_len < pkt->hdr_len))
		return -ERR_PKT_INVALID_LEN;

	pkt->src_port = th->src_port;
	pkt->dst_port = th->dst_port;

	TCP_SEG(pkt)->seq   = ntohl(th->sent_seq);
	TCP_SEG(pkt)->ack   = ntohl(th->recv_ack);
	TCP_SEG(pkt)->wnd   = ntohs(th->rx_win);
	TCP_SEG(pkt)->flags = th->tcp_flags;
	TCP_SEG(pkt)->len   = ip_payload_len - tcp_hdr_len;
	TCP_SEG(pkt)->opt_len = tcp_hdr_len - sizeof(struct rte_tcp_hdr);

	pkt->l5_len = TCP_SEG(pkt)->len;
	pkt->tail = pkt;
	pkt->nr_read_seg = 1;

	return 0;
}

extern struct packet_pool *generic_pkt_pool;
int packet_pool_create(struct packet_pool *pool, double percent,
		       uint32_t mbuf_size, const char *fmt, ...);

#endif
