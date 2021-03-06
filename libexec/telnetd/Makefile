# $FreeBSD$

# Do not define -DKLUDGELINEMODE, as it does not interact well with many
# telnet implementations.

.include <src.opts.mk>

TELNETDIR=	${.CURDIR}/../../contrib/telnet
.PATH:		${TELNETDIR}/telnetd

PROG=		telnetd
MAN=		telnetd.8

SRCS=		global.c slc.c state.c sys_term.c telnetd.c \
		termstat.c utility.c

WARNS?=		2
WFORMAT?=	0

CFLAGS+=	-DLINEMODE -DUSE_TERMIO -DDIAGNOSTICS -DOLD_ENVIRON \
		-DENV_HACK -DSTREAMSPTY

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=	-DINET6
.endif

CFLAGS+=	-I${TELNETDIR}

LIBTELNET=	${.OBJDIR}/../../lib/libtelnet/libtelnet.a

DPADD=		${LIBUTIL} ${LIBTERMCAPW} ${LIBTELNET}
LDADD=		-lutil -ltermcapw ${LIBTELNET}

.if ${MK_OPENSSL} != "no"
SRCS+=		authenc.c
CFLAGS+=	-DAUTHENTICATION -DENCRYPTION
DPADD+=		${LIBMP} ${LIBCRYPTO} ${LIBCRYPT} ${LIBPAM}
LDADD+=		-lmp -lcrypto -lcrypt ${MINUSLPAM}
.endif

.if ${MK_KERBEROS_SUPPORT} != "no"
CFLAGS+=	-DKRB5 -DFORWARD -Dnet_write=telnet_net_write
DPADD+=		${LIBKRB5} ${LIBHX509} ${LIBASN1} ${LIBROKEN} ${LIBCOM_ERR}
LDADD+=		-lkrb5 -lhx509 -lasn1 -lroken -lcom_err
.endif

.include <bsd.prog.mk>
