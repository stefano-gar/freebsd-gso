#  $FreeBSD$

.PATH:	${.CURDIR}/../libat91

P=boot0iic
FILES=${P}
SRCS=arm_init.S main.c
MAN=
LDFLAGS=-e 0 -T ${.CURDIR}/../linker.cfg
OBJS+=  ${SRCS:N*.h:R:S/$/.o/g}

.include <bsd.prog.mk>

CFLAGS+=-DBOOT_BOOT0
