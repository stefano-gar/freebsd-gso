#include "opt_inet6.h"

#include <net/gso.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/tcpip.h>
#include <netinet/udp_var.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#include <net/if.h>
#include <net/vnet.h>
#include <net/ethernet.h>
#include <net/if_vlan_var.h>

#include <machine/in_cksum.h>

/* Define the new net.gso sysctl tree. */
SYSCTL_NODE(_net, OID_AUTO, gso, CTLFLAG_RW, NULL,
	"GSO settings and statistics");
/*
 * Define net.gso.dev sysctl tree.
 * It contains the GSO parameters for each interface.
 */
SYSCTL_NODE(_net_gso, OID_AUTO, dev, CTLFLAG_RW, NULL,
	"GSO device settings");

#ifdef GSO_STATS
struct gsostat gsostat;
SYSCTL_STRUCT(_net_gso, OID_AUTO, stats, CTLFLAG_RW,
	&gsostat, gsostat,
	"GSO statistics (struct gsostat, net/gso.h)");
#endif

MALLOC_DEFINE(M_GSO, "GSO", "GSO internals");

/*
 * Default GSO parameters for each interface.
 */
#define GSO_INIT_MAXPACKET 	IP_MAXPACKET
#define GSO_INIT_ENABLE		1

/*
 * Array of function pointers that execute the GSO depending on packet type
 */
int (*gso_functions[GSO_END_OF_TYPE]) (struct ifnet*, struct mbuf*, u_int);


/*
 * XXX-ste: Maybe this function must be moved into kern/uipc_mbuf.c
 *
 * Create a queue of packets/segments which fit the given mss + hdr_len.
 * m0 points to mbuf chain to be segmented.
 * This function splits the payload (m0-> m_pkthdr.len - hdr_len)
 * into segments of length MSS bytes and then copy the first hdr_len bytes
 * from m0 at the top of each segment.
 * If hdr2_buf is not NULL (hdr2_len is the buf length), it is copied
 * in each segment after the first hdr_len bytes
 *
 * Return the new queue with the segments on success, NULL on failure.
 * (the mbuf queue is freed in this case).
 * nsegs contains the number of segments generated.
 */
static struct mbuf *
m_seg(struct mbuf *m0, int hdr_len, int mss, int *nsegs, char * hdr2_buf, int hdr2_len)
{
	int error = 0;
	int off = 0, n, firstlen;
	struct mbuf **mnext, *mseg;
	char *hdr_buf;
	int total_len = m0->m_pkthdr.len;

	/*
	 * Segmentation useless
	 */
	if (total_len <= hdr_len + mss) {
		return m0;
	}

	/* TODO: check all parameters*/
	if (mss < 0) {
#ifdef GSO_DEBUG
		D("mss < 0 - mss= %d \n", mss);
#endif
		goto err;
	}

	if (!hdr2_buf || hdr2_len <= 0) {
		hdr2_buf = NULL;
		hdr2_len = 0;
	}

	off = hdr_len + mss;
	firstlen = mss; /* first segment stored in the original mbuf */

	mnext = &(m0->m_nextpkt); /* pointer to next packet */

	for (n = 1; off < total_len; off += mss, n++) {
		struct mbuf *m;
		/*
		 * Copy the header from the original packet
		 * and create a new mbuf chain
		 */
		if (MHLEN < hdr_len) {
			m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
#ifdef GSO_STATS
			GSOSTAT_INC(mseg.gsos_mclget);
#endif
		} else
			m = m_gethdr(M_NOWAIT, MT_DATA);

		if (m == NULL) {
#ifdef GSO_DEBUG
			D("MGETHDR error\n");
#endif
			goto err;
		}

		m_copydata(m0, 0, hdr_len, mtod(m, caddr_t));

		m->m_len = hdr_len;
		/*
		 * if the optional header is present, copy it
		 */
		if (hdr2_buf) {
			m_copyback(m, hdr_len, hdr2_len, hdr2_buf);
		}

		m->m_flags |= (m0->m_flags & M_COPYFLAGS);
		if (off + mss >= total_len) {		/* last segment */
			mss = total_len - off;
		}
		/*
		 * Copy the payload from original packet
		 */
		mseg = m_copym(m0, off, mss, M_NOWAIT);
		if (mseg == NULL) {
			m_freem(m);
#ifdef GSO_DEBUG
			D("m_copym error\n");
#endif
			goto err;
		}
		m_cat(m, mseg);

		m->m_pkthdr.len = hdr_len + hdr2_len + mss;
		m->m_pkthdr.rcvif = m0->m_pkthdr.rcvif;
		/*
		 * Copy the checksum flags and data (in_cksum() need this)
		 */
		m->m_pkthdr.csum_flags = m0->m_pkthdr.csum_flags;
		m->m_pkthdr.csum_data = m0->m_pkthdr.csum_data;
		m->m_pkthdr.tso_segsz = m0->m_pkthdr.tso_segsz;

		*mnext = m;
		mnext = &(m->m_nextpkt);
	}

	/*
	 * Update first segment.
	 * If the optional header is present, is necessary
	 * to insert it into the first segment.
	 */
	if (!hdr2_buf) {
		m_adj(m0, hdr_len + firstlen - total_len);
		m0->m_pkthdr.len = hdr_len + firstlen;
	} else {
		mseg = m_copym(m0, hdr_len, firstlen, M_NOWAIT);
		if (mseg == NULL) {
#ifdef GSO_DEBUG
			D("m_copym error\n");
#endif
			goto err;
		}
		m_adj(m0, hdr_len - total_len);
		m_copyback(m0, hdr_len, hdr2_len, hdr2_buf);
		m_cat(m0, mseg);
		m0->m_pkthdr.len = hdr_len + hdr2_len + firstlen;
	}

	if (nsegs != NULL) {
		*nsegs = n;
	}
	return m0;
err:
	while (m0 != NULL) {
		mseg = m0->m_nextpkt;
		m_freem(m0);
		m0 = mseg;
	}
	return NULL;
}


/*
 * Wrappers of IPv4 checksum functions
 */
static inline void
gso_ipv4_data_cksum(struct mbuf *m, struct ip *ip, int mac_hlen)
{
	m->m_data += mac_hlen;
	m->m_len -= mac_hlen;
	m->m_pkthdr.len -= mac_hlen;
	ip->ip_len = ntohs(ip->ip_len);	/*needed for cksum*/

	in_delayed_cksum(m);

	ip->ip_len = htons(ip->ip_len);
	m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	m->m_len += mac_hlen;
	m->m_pkthdr.len += mac_hlen;
	m->m_data -= mac_hlen;
}

static inline void
gso_ipv4_hdr_cksum(struct mbuf *m, struct ip *ip, int mac_hlen, int ip_hlen)
{
	m->m_data += mac_hlen;

	ip->ip_sum = in_cksum(m, ip_hlen);

	m->m_pkthdr.csum_flags &= ~CSUM_IP;
	m->m_data -= mac_hlen;
}

/*
 * Structure that contains the state during the TCP segmentation
 */
struct gso_ip_tcp_state {
	void	(*update)
		(struct gso_ip_tcp_state*, struct mbuf*);
	void	(*internal)
		(struct gso_ip_tcp_state*, struct mbuf*);
	union {
		struct ip *ip;
#ifdef INET6
		struct ip6_hdr *ip6;
#endif
	} hdr;
	struct tcphdr *tcp;
	int mac_hlen;
	int ip_hlen;
	int tcp_hlen;
	int hlen;
	int pay_len;
	int sw_csum;
	uint32_t tcp_seq;
	uint16_t ip_id;
};

/*
 * Update the pointers to TCP and IPv4 headers
 */
static inline void
gso_ipv4_tcp_update(struct gso_ip_tcp_state *state, struct mbuf *m)
{
	state->hdr.ip = (struct ip *)(mtod(m, uint8_t *) + state->mac_hlen);
	state->tcp = (struct tcphdr *)((caddr_t)(state->hdr.ip) + state->ip_hlen);
	state->pay_len = m->m_pkthdr.len - state->hlen;
}

/*
 * Set properly the TCP and IPv4 headers
 */
static inline void
gso_ipv4_tcp_internal(struct gso_ip_tcp_state *state, struct mbuf *m)
{
	/*
	 * Update IP header
	 */
	state->hdr.ip->ip_id = htons((state->ip_id)++);
	state->hdr.ip->ip_len = htons(m->m_pkthdr.len - state->mac_hlen);
	/*
	 * TCP Checksum
	 */
	state->tcp->th_sum = 0;
	state->tcp->th_sum = in_pseudo(state->hdr.ip->ip_src.s_addr,
			state->hdr.ip->ip_dst.s_addr,
			htons(state->tcp_hlen + IPPROTO_TCP + state->pay_len));
	/*
	 * Checksum HW not supported (TCP)
	 */
	if (state->sw_csum & CSUM_DELAY_DATA) {
		gso_ipv4_data_cksum(m, state->hdr.ip, state->mac_hlen);
	}

	state->tcp_seq += state->pay_len;
	/*
	 * IP Checksum
	 */
	state->hdr.ip->ip_sum = 0;
	/*
	 * Checksum HW not supported (IP)
	 */
	if (state->sw_csum & CSUM_IP) {
		gso_ipv4_hdr_cksum(m, state->hdr.ip, state->mac_hlen, state->ip_hlen);
	}
}


/*
 * Updates the pointers to TCP and IPv6 headers
 */
#ifdef INET6
static inline void
gso_ipv6_tcp_update(struct gso_ip_tcp_state *state, struct mbuf *m)
{
	state->hdr.ip6 = (struct ip6_hdr *)(mtod(m, uint8_t *) + state->mac_hlen);
	state->tcp = (struct tcphdr *)((caddr_t)(state->hdr.ip6) + state->ip_hlen);
	state->pay_len = m->m_pkthdr.len - state->hlen;
}

/*
 * Sets properly the TCP and IPv6 headers
 */
static inline void
gso_ipv6_tcp_internal(struct gso_ip_tcp_state *state, struct mbuf *m)
{
	state->hdr.ip6->ip6_plen = htons(m->m_pkthdr.len -
					state->mac_hlen - state->ip_hlen);
	/*
	 * TCP Checksum
	 */
	state->tcp->th_sum = 0;
	state->tcp->th_sum = in6_cksum_pseudo(state->hdr.ip6,
				state->tcp_hlen + state->pay_len, IPPROTO_TCP, 0);
	/*
	 * Checksum HW not supported (TCP)
	 */
	if (state->sw_csum & CSUM_DELAY_DATA_IPV6) {
		in6_delayed_cksum(m, m->m_pkthdr.len - state->ip_hlen - state->mac_hlen,
				state->ip_hlen + state->mac_hlen);

		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA_IPV6;
	}
	state->tcp_seq += state->pay_len;
}
#endif /* INET6 */

/*
 * Init the state during the TCP segmentation
 */
static inline void
gso_ip_tcp_init_state(struct gso_ip_tcp_state *state, struct ifnet *ifp, struct mbuf *m, int mac_hlen, int ip_hlen, int isipv6)
{
#ifdef INET6
	if (isipv6) {
		state->hdr.ip6 = (struct ip6_hdr *)(mtod(m, uint8_t *) + mac_hlen);
		state->tcp = (struct tcphdr *)((caddr_t)(state->hdr.ip6) + ip_hlen);
		state->update = gso_ipv6_tcp_update;
		state->internal = gso_ipv6_tcp_internal;
	} else
#endif
	{
		state->hdr.ip = (struct ip *)(mtod(m, uint8_t *) + mac_hlen);
		state->ip_id = ntohs(state->hdr.ip->ip_id);
		state->tcp = (struct tcphdr *)((caddr_t)(state->hdr.ip) + ip_hlen);
		state->update = gso_ipv4_tcp_update;
		state->internal = gso_ipv4_tcp_internal;
	}

	state->mac_hlen = mac_hlen;
	state->ip_hlen = ip_hlen;
	state->tcp_hlen = state->tcp->th_off << 2;
	state->hlen = mac_hlen + ip_hlen + state->tcp_hlen;
	state->tcp_seq = ntohl(state->tcp->th_seq);
	state->sw_csum = m->m_pkthdr.csum_flags & ~ifp->if_hwassist;
}

/*
 * GSO on TCP/IP (v4 or v6)
 */
static int
gso_ip_tcp(struct ifnet *ifp, struct mbuf *m0, struct gso_ip_tcp_state *state)
{
	struct mbuf *m, *m_tx;
	int error = 0;
	int mss = 0;
	int nsegs = 0;
#ifdef GSO_STATS
	int total_len = m0->m_pkthdr.len;
#endif

	if (m0->m_pkthdr.csum_flags & ifp->if_hwassist & CSUM_TSO) {/* do TSO */
		mss = ifp->if_hw_tsomax - state->ip_hlen - state->tcp_hlen;
	} else {
		mss = m0->m_pkthdr.tso_segsz;
	}

	m0 = m_seg(m0, state->hlen, mss, &nsegs, 0, 0);
	if (m0 == NULL) {
		m = m0;
		error = ENOBUFS;		/* XXX ok? */
		goto err;
	}
	/*
	 * XXX-ste: can this happen?
	 */
	if (m0->m_nextpkt == NULL) {
#ifdef GSO_DEBUG
		D("only 1 segment");
#endif
		error = ((ifp->if_transmit)(ifp, m0));
		return error;
	}
#ifdef GSO_STATS
	GSOSTAT_SET_MAX(tcp.gsos_max_mss,mss);
	GSOSTAT_SET_MIN(tcp.gsos_min_mss,mss);
	GSOSTAT_ADD(tcp.gsos_osegments,nsegs);
#endif

	/* firts pkt */
	m = m0;

	state->update(state, m);

	do {
		state->tcp->th_flags &= ~ (TH_FIN | TH_PUSH);

		state->internal(state, m);

		m_tx = m;
		m = m->m_nextpkt;
		m_tx->m_nextpkt = NULL;

		if (error = ((ifp->if_transmit)(ifp, m_tx))) {
			/*
			 * XXX: If a segment can not be sent, discard the following
			 * segments and propagate the erorr to the upper levels.
			 * In this way the TCP retrasmits all the initial packet.
			 */
#ifdef GSO_DEBUG
			D("if_transmit error\n");
#endif
			goto err;
		}

		state->update(state, m);

		state->tcp->th_flags &= ~ TH_CWR;
		state->tcp->th_seq = htonl(state->tcp_seq);
	} while (m->m_nextpkt);

	/* last pkt */
	state->internal(state, m);

	error = ((ifp->if_transmit)(ifp, m));

#ifdef GSO_DEBUG
	if (error) {
		D("last if_transmit error\n");
		D("error - type = %d \n", error);
	}
#endif
#ifdef GSO_STATS
	if (!error) {
		GSOSTAT_INC(tcp.gsos_segmented);
		GSOSTAT_SET_MAX(tcp.gsos_maxsegmented, total_len);
		GSOSTAT_SET_MIN(tcp.gsos_minsegmented, total_len);
		GSOSTAT_ADD(tcp.gsos_totalbyteseg, total_len);
	}
#endif
	return error;

err:
#ifdef GSO_DEBUG
	D("error - type = %d \n", error);
#endif
	while (m != NULL) {
		m_tx = m->m_nextpkt;
		m_freem(m);
		m = m_tx;
	}
	return error;
}

/*
 * GSO on TCP/IPv4
 */
static int
gso_ipv4_tcp(struct ifnet *ifp, struct mbuf *m0, u_int mac_hlen)
{
	struct ip *ip;
	struct gso_ip_tcp_state state;
	int hlen;
	int ip_hlen;

	hlen = mac_hlen + sizeof(struct ip);

	if (m0->m_len < hlen) {
#ifdef GSO_DEBUG
		D("m_len < hlen - m_len: %d hlen: %d", m0->m_len, hlen);
#endif
		m0 = m_pullup(m0, hlen);
		if (m0 == NULL) {
			return ENOBUFS;
		}
	}
	ip = (struct ip *)(mtod(m0, uint8_t *) + mac_hlen);
	ip_hlen = ip->ip_hl << 2;

	hlen = mac_hlen + ip_hlen + sizeof(struct tcphdr);

	if (m0->m_len < hlen) {
#ifdef GSO_DEBUG
		D("m_len < hlen - m_len: %d hlen: %d", m0->m_len, hlen);
#endif
		m0 = m_pullup(m0, hlen);
		if (m0 == NULL) {
			return ENOBUFS;
		}
	}

	gso_ip_tcp_init_state(&state, ifp, m0, mac_hlen, ip_hlen, 0);

	return gso_ip_tcp(ifp, m0, &state);
}

/*
 * GSO on TCP/IPv6
 */
#ifdef INET6
static int
gso_ipv6_tcp(struct ifnet *ifp, struct mbuf *m0, u_int mac_hlen)
{
	struct ip6_hdr *ip6;
	struct gso_ip_tcp_state state;
	int hlen;
	int ip_hlen;

	hlen = mac_hlen + sizeof(struct ip6_hdr);

	if (m0->m_len < hlen) {
#ifdef GSO_DEBUG
		D("m_len < hlen - m_len: %d hlen: %d", m0->m_len, hlen);
#endif
		m0 = m_pullup(m0, hlen);
		if (m0 == NULL) {
			return ENOBUFS;
		}
	}
	ip6 = (struct ip6_hdr *)(mtod(m0, uint8_t *) + mac_hlen);
	ip_hlen = ip6_lasthdr(m0, mac_hlen, IPPROTO_IPV6, NULL) - mac_hlen;

	hlen = mac_hlen + ip_hlen + sizeof(struct tcphdr);

	if (m0->m_len < hlen) {
#ifdef GSO_DEBUG
		D("m_len < hlen - m_len: %d hlen: %d", m0->m_len, hlen);
#endif
		m0 = m_pullup(m0, hlen);
		if (m0 == NULL) {
			return ENOBUFS;
		}
	}

	gso_ip_tcp_init_state(&state, ifp, m0, mac_hlen, ip_hlen, 1);

	return gso_ip_tcp(ifp, m0, &state);
}
#endif /* INET6 */

/*
 * IPv4 fragmentation (for UDP)
 */
static int
gso_ipv4_frag(struct ifnet *ifp, struct mbuf *m0, u_int mac_hlen)
{
	int error = 0;
	struct mbuf *m, *m_tx;
	struct ip *ip;
	int hlen;
	int ip_hlen;
	int mss;
	int sw_csum;
	int off;
	int nfrags = 0;
#ifdef GSO_STATS
	int total_len = m0->m_pkthdr.len;
#endif

	hlen = mac_hlen + sizeof(struct ip);

	if (m0->m_len < hlen) {
#ifdef GSO_DEBUG
		D("m_len < hlen - m_len: %d hlen: %d", m0->m_len, hlen);
#endif
		m0 = m_pullup(m0, hlen);
		if (m0 == NULL) {
			m = m0;
			error = ENOBUFS;
			goto err;
		}
	}

	ip = (struct ip *)(mtod(m0, uint8_t *) + mac_hlen);
	ip_hlen = ip->ip_hl << 2;

	hlen = mac_hlen + ip_hlen;

	/* XXX: redo pullup?? */

	/*
	 * Payload checksum calculation
	 */
	if (m0->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
		gso_ipv4_data_cksum(m0, ip, mac_hlen);
	}

	mss = m0->m_pkthdr.tso_segsz & ~7;

	/*
	 * Software checksum flags
	 */
	sw_csum = m0->m_pkthdr.csum_flags & ~ifp->if_hwassist;

	m0 = m_seg(m0, hlen, mss, &nfrags, 0, 0);
	if (m0 == NULL) {
		m = m0;
		error = ENOBUFS;                /* XXX ok? */
		goto err;
	}

#ifdef GSO_STATS
	GSOSTAT_SET_MAX(udp.gsos_max_mss,mss);
	GSOSTAT_SET_MIN(udp.gsos_min_mss,mss);
	GSOSTAT_ADD(udp.gsos_osegments,nfrags);
#endif

	/* first frag */
	m = m0;

	ip = (struct ip *)(mtod(m, uint8_t *) + mac_hlen);
	off = ntohs(ip->ip_off);

	do {
		ip->ip_off = htons((off >> 3) | IP_MF);
		ip->ip_len = htons(m->m_pkthdr.len - mac_hlen);
		ip->ip_sum = 0;
		if (sw_csum & CSUM_IP) {
			gso_ipv4_hdr_cksum(m, ip, mac_hlen, ip_hlen);
		}
		off += m->m_pkthdr.len - hlen;

		m_tx = m;
		m = m->m_nextpkt;
		m_tx->m_nextpkt = NULL;

		if (error = ((ifp->if_transmit)(ifp, m_tx))) {
#ifdef GSO_DEBUG
			D("if_transmit error\n");
			D("m->m_pkthdr.len: %d", m_tx->m_pkthdr.len);
#endif
			goto err;
		}

		ip = (struct ip *)(mtod(m, uint8_t *) + mac_hlen);

	} while (m->m_nextpkt);

	/* last pkt */
	ip->ip_off = htons((off >> 3));
	ip->ip_len = htons(m->m_pkthdr.len - mac_hlen);
	ip->ip_sum = 0;
	if (sw_csum & CSUM_IP) {
		gso_ipv4_hdr_cksum(m, ip, mac_hlen, ip_hlen);
	}

	error = ((ifp->if_transmit)(ifp, m));

#ifdef GSO_DEBUG
	if (error) {
		D("last if_transmit error\n");
		D("error - type = %d \n", error);
		D("m->m_pkthdr.len: %d", m->m_pkthdr.len);
	}
#endif
#ifdef GSO_STATS
	if (!error) {
		GSOSTAT_INC(udp.gsos_segmented);
		GSOSTAT_SET_MAX(udp.gsos_maxsegmented, total_len);
		GSOSTAT_SET_MIN(udp.gsos_minsegmented, total_len);
		GSOSTAT_ADD(udp.gsos_totalbyteseg, total_len);
	}
#endif
        return error;

 err:
#ifdef GSO_DEBUG
	D("error - type = %d \n", error);
#endif
	while (m != NULL) {
		m_tx = m->m_nextpkt;
		m_freem(m);
		m = m_tx;
	}
        return error;
}


/*
 * IPv6 fragmentation (for UDP)
 */
#ifdef INET6
static int
gso_ipv6_frag(struct ifnet *ifp, struct mbuf *m0, u_int mac_hlen)
{
	int error = 0;
	struct mbuf *m, *m_tx, *m_ip6f;
	struct ip6_hdr *ip6;
	struct ip6_frag ip6f, *ip6f_p;
	uint32_t id;
	int hlen, mss;
	int sw_csum;
	int off, off_ip6f;
	int ip_hlen, nextproto;
	int nfrags = 0;
#ifdef GSO_STATS
	int total_len = m0->m_pkthdr.len;
#endif

	hlen = mac_hlen + sizeof(struct ip6_hdr);

	if (m0->m_len < hlen) {
#ifdef GSO_DEBUG
		D("m_len < hlen - m_len: %d hlen: %d", m0->m_len, hlen);
#endif
		m0 = m_pullup(m0, hlen);
		if (m0 == NULL) {
			m = m0;
			error = ENOBUFS;
			goto err;
		}
	}
	ip6 = (struct ip6_hdr *)(mtod(m0, uint8_t *) + mac_hlen);
	hlen = ip6_lasthdr(m0, mac_hlen, IPPROTO_IPV6, &nextproto);
	ip_hlen = hlen - mac_hlen;

	/* XXX: redo pullup?? */

	/*
	 * Payload checksum calculation
	 */
	if (m0->m_pkthdr.csum_flags & CSUM_DELAY_DATA_IPV6) {
		in6_delayed_cksum(m0, m0->m_pkthdr.len - hlen, hlen);

		m0->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA_IPV6;
	}

	/*
	 * XXX-ste: ip6_get_prevhdr is deprecated
	 * find an alternative:
	 * 	-set in ip6_output()?
	 */
	{
		char *lastnxtp;
		m0->m_data += mac_hlen;

		lastnxtp = ip6_get_prevhdr(m0, ip_hlen);
		*lastnxtp = IPPROTO_FRAGMENT;

		m0->m_data -= mac_hlen;
	}

	mss = m0->m_pkthdr.tso_segsz & ~7;
	/*
	 * Software checksum flags
	 */
	sw_csum = m0->m_pkthdr.csum_flags & ~ifp->if_hwassist;

	id = htonl(ip6_randomid());
	ip6f.ip6f_ident = id;
	ip6f.ip6f_nxt = nextproto;
	ip6f.ip6f_reserved = 0;

	m0 = m_seg(m0, hlen, mss, &nfrags,(char *) &ip6f, sizeof(struct ip6_frag));
	if (m0 == NULL) {
		m = m0;
		error = ENOBUFS;                /* XXX ok? */
		goto err;
	}
#ifdef GSO_STATS
	GSOSTAT_SET_MAX(udp.gsos_max_mss,mss);
	GSOSTAT_SET_MIN(udp.gsos_min_mss,mss);
	GSOSTAT_ADD(udp.gsos_osegments,nfrags);
#endif
	/* first frag */
	m = m0;
	off = 0;
	ip6 = (struct ip6_hdr *)(mtod(m, uint8_t *) + mac_hlen);
	m_ip6f = m_getptr(m, hlen, &off_ip6f);
	ip6f_p = (struct ip6_frag *)(mtod(m_ip6f, uint8_t *) + off_ip6f);
	do {
		ip6f_p->ip6f_offlg = htons((u_short)((off) & ~7)) | IP6F_MORE_FRAG;
		ip6->ip6_plen = htons(m->m_pkthdr.len - mac_hlen - sizeof(struct ip6_hdr));
		off += m->m_pkthdr.len - hlen - sizeof(struct ip6_frag);

		m_tx = m;
		m = m->m_nextpkt;
		m_tx->m_nextpkt = NULL;

		if (error = ((ifp->if_transmit)(ifp, m_tx))) {
#ifdef GSO_DEBUG
			D("if_transmit error\n");
#endif
			goto err;
		}
		ip6 = (struct ip6_hdr *)(mtod(m, uint8_t *) + mac_hlen);
		m_ip6f = m_getptr(m, hlen, &off_ip6f);
		ip6f_p = (struct ip6_frag *)(mtod(m_ip6f, uint8_t *) + off_ip6f);
	} while (m->m_nextpkt);

	/* last pkt */
	ip6f_p->ip6f_offlg = htons((u_short)((off) & ~7));
	ip6->ip6_plen = htons(m->m_pkthdr.len - mac_hlen - sizeof(struct ip6_hdr));
	error = ((ifp->if_transmit)(ifp, m));

#ifdef GSO_DEBUG
	if (error) {
		D("last if_transmit error\n");
		D("error - type = %d \n", error);
	}
#endif
#ifdef GSO_STATS
	if (!error) {
		GSOSTAT_INC(udp.gsos_segmented);
		GSOSTAT_SET_MAX(udp.gsos_maxsegmented, total_len);
		GSOSTAT_SET_MIN(udp.gsos_minsegmented, total_len);
		GSOSTAT_ADD(udp.gsos_totalbyteseg, total_len);
	}
#endif
	return error;
 err:
#ifdef GSO_DEBUG
	D("error - type = %d \n", error);
#endif
	while (m != NULL) {
		m_tx = m->m_nextpkt;
		m_freem(m);
		m = m_tx;
	}
	return error;
}
#endif /* INET6 */

int
gso_none(struct ifnet *ifp, struct mbuf *m, u_int mac_hlen)
{
	/*
	 * GSO is disable, we send the packet directly to the device driver
	 */
	return ((ifp->if_transmit)(ifp, m));
}

int
gso_dispatch(struct ifnet *ifp, struct mbuf *m, u_int mac_hlen)
{
	int error = 0;
	u_int gso_flags;	/* XXX: is type correct? */

	gso_flags = CSUM_TO_GSO(m->m_pkthdr.csum_flags);

	if (gso_flags >= GSO_END_OF_TYPE) {
#ifdef GSO_DEBUG
		D("gso_flags out of range or null [%d]", gso_flags);
#endif
		m_freem(m);
		return ENOPROTOOPT;
	}

	error = gso_functions[gso_flags](ifp, m, mac_hlen);

#ifdef GSO_DEBUG
	if (error)
		D("error segmentation - type = %d\n", error);
#endif
	return error;
}

static inline void
gso_init()
{
	gso_functions[GSO_NONE] = gso_none;
	gso_functions[GSO_TCP4] = gso_ipv4_tcp;
	gso_functions[GSO_UDP4] = gso_ipv4_frag;
#ifdef INET6
	gso_functions[GSO_TCP6] = gso_ipv6_tcp;
	gso_functions[GSO_UDP6] = gso_ipv6_frag;
#endif /* INET6 */
}

void
gso_ifattach(struct ifnet *ifp)
{
	struct if_gso *if_gso;
	struct sysctl_ctx_list *clist;
	struct sysctl_oid *oid_root, *oid_p;

	/*
	 *
	 */
	if (gso_functions[GSO_NONE] != gso_none) {
		gso_init();
	}

	/*
	 * Initialization of GSO parameters
	 */
	if_gso = malloc(sizeof(struct if_gso), M_GSO, M_WAITOK | M_ZERO);
	if_gso->max_burst = GSO_INIT_MAXPACKET;
	if_gso->enable = GSO_INIT_ENABLE;

	/*
	 * Creation of sysctl to set GSO parameters for this interface (ifp)
	 */
	clist = &(if_gso->clist);
	sysctl_ctx_init(clist);
	oid_root = SYSCTL_ADD_NODE(clist, SYSCTL_STATIC_CHILDREN(_net_gso_dev),
			OID_AUTO, ifp->if_xname, CTLFLAG_RW, 0, "if name");
	oid_p = SYSCTL_ADD_UINT(clist, SYSCTL_CHILDREN(oid_root),
			OID_AUTO, "max_burst", CTLFLAG_RW, &(if_gso->max_burst),
			0, "GSO burst length limit");
	oid_p = SYSCTL_ADD_UINT(clist, SYSCTL_CHILDREN(oid_root),
			OID_AUTO, "enable_gso", CTLFLAG_RW, &(if_gso->enable),
			0, "GSO enable (!=0)");
	/*
	 * Put if_gso inside struct ifnet
	 */
	W_IF_GSO(ifp) = if_gso;
}

void
gso_ifdetach(struct ifnet *ifp)
{
	struct if_gso *if_gso;

	if_gso = IF_GSO(ifp);
	if (if_gso == NULL)
		return;

	W_IF_GSO(ifp) = NULL;

	if (sysctl_ctx_free(&(if_gso->clist))) {
#ifdef GSO_DEBUG
		D("error sysctl_ctx_free");
#endif
	}

	free(if_gso, M_GSO);
}
