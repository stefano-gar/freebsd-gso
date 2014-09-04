/*
 * Copyright (C) 2014, Stefano Garzarella - Universita` di Pisa.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NET_GSO_H_
#define _NET_GSO_H_

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/stdint.h> /* UINT64_MAX */
#include <sys/systm.h>	/* memset */
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#else	/* !_KERNEL */
#include <stdint.h>		/* UINT64_MAX */
#include <string.h>		/* memset */
#endif	/* _KERNEL */

#define GSO_SYSCTL_STATS "net.gso.stats"

/*
 * Structs used to collect statistics
 */
struct gsostat_proto {
	uint64_t gsos_segmented;		/* total burst segmented */
	uint64_t gsos_osegments; 		/* output segments created */
	uint64_t gsos_maxsegmented;		/* max size of segmented packets */
	uint64_t gsos_minsegmented;		/* min size of segmented packets */
	uint64_t gsos_totalbyteseg;		/* total bytes segmented */
	uint64_t gsos_max_mss;			/* max Maximum Segment Size */
	uint64_t gsos_min_mss;			/* min Maximum Segment Size */
};

struct gsostat {
	struct gsostat_proto tcp;			/* TCP (IPv4/IPv6) statistics */
	struct gsostat_proto ipv4_frag;		/* IPv4 frag (UDP) statistics */
	struct gsostat_proto ipv6_frag;		/* IPv6 frag (UDP) statistics */
};

/*
 *	Functions used to reset statistics
 */
static void
gsostat_proto_reset(struct gsostat_proto* gsp)
{
	memset(gsp, 0, sizeof(struct gsostat_proto));
	gsp->gsos_minsegmented = UINT64_MAX;
	gsp->gsos_min_mss = UINT64_MAX;
}

static void
gsostat_reset(struct gsostat* gs)
{
	gsostat_proto_reset(&(gs->tcp));
	gsostat_proto_reset(&(gs->ipv4_frag));
	gsostat_proto_reset(&(gs->ipv6_frag));
}

#ifdef _KERNEL

/*
 * Enable gso statistics
 *
 * The statistics are accessible through sysctl net.gso.stats
 * (struct gsostat).
 */

#define GSO_STATS

/* In-kernel macros to update stats */
#define GSOSTAT_SET(name, val)		_gsostat.name = val;
#define GSOSTAT_ADD(name, val)  	_gsostat.name += (val);
#define GSOSTAT_INC(name)       	GSOSTAT_ADD(name, 1)
#define GSOSTAT_DEC(name)			GSOSTAT_ADD(name, -1);
#define GSOSTAT_SET_MAX(name, val)	_gsostat.name = MAX(_gsostat.name,val);
#define GSOSTAT_SET_MIN(name, val)	_gsostat.name = MIN(_gsostat.name,val);


/*
 * This struct contains all fields needed to support GSO on each NIC.
 * It is stored in struct ifnet.
 *
 * The GSO parameters can be modified through these sysctl:
 *	sysctl net.gso.dev."ifname".max_burst
 *	sysctl net.gso.dev."ifname".enable_gso
 */
struct if_gso {  			/*XXX esposta o no??? */
	struct sysctl_ctx_list clist;	/* sysctl ctx for this interface */

	/* GSO parameters for each interface */
	u_int max_burst;		/* GSO burst length limit */
	u_int enable;			/* GSO enable (!=0)*/
};

/*
 * IF_GSO returns a pointer to the struct if_gso from the ifp (struct ifnet *)
 * W_IF_GSO is used to write it
 */
#define W_IF_GSO(_ifp)    	((_ifp)->if_pspare[2])
#define IF_GSO(_ifp)    	((struct if_gso *)W_IF_GSO(_ifp))

/*
 * T_GSOMAX can be used to read/write the value of gsomax in tcpcb (TCP control block).
 * Temporarily it is contained in a spare field.
 */
#define T_GSOMAX(_tp)		((_tp)->t_ispare[5])


/*
 * GSO types
 */
#define CSUM_GSO_OFFSET 16

enum gso_type {
	GSO_NONE,
	GSO_TCP4,
	GSO_TCP6,
	GSO_UDP4,
	GSO_UDP6,
/*
 *	GSO_SCTP4, TODO
 *	GSO_SCTP6,
 */
	GSO_END_OF_TYPE
};

/*
 * Convert gso_type to CSUM flags (sys/mbuf.h) or vice versa
 */
#define GSO_TO_CSUM(x) ((x << CSUM_GSO_OFFSET) & CSUM_GSO_MASK)
#define CSUM_TO_GSO(x) ((x & CSUM_GSO_MASK) >> CSUM_GSO_OFFSET)

/*
 * gso_dispatch() performs segmentation and invokes if_transmit() for each
 * 	segment generated.
 *
 * gso_ifattach() initializes a struct if_gso, allocating a new sysctl context
 * 	and creating the sysctl nodes to change the parameters for each interface.
 *
 * gso_ifdetach() frees the memory allocated by gso_ifattach().
 */
int 	gso_dispatch(struct ifnet *ifp, struct mbuf *m, u_int mac_hlen);
void 	gso_ifattach(struct ifnet *ifp);
void 	gso_ifdetach(struct ifnet *ifp);



/* DEBUG utility */

//#define GSO_DEBUG
//#define GSO_TEST

/* Printf utility by netmap */
#define ND(format, ...)
#define D(format, ...)                                          \
        do {                                                    \
                struct timeval __xxts;                          \
                microtime(&__xxts);                             \
                printf("%03d.%06d %s [%d] " format "\n",        \
                (int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
                __FUNCTION__, __LINE__, ##__VA_ARGS__);         \
        } while (0)

/* rate limited, lps indicates how many per second */
#define RD(lps, format, ...)                                    \
        do {                                                    \
                static int t0, __cnt;                           \
                if (t0 != time_second) {                        \
                        t0 = time_second;                       \
                        __cnt = 0;                              \
                }                                               \
                if (__cnt++ < lps)                              \
                        D(format, ##__VA_ARGS__);               \
        } while (0)


#endif  /* _KERNEL */

#endif  /* !_NET_GSO_H_ */
