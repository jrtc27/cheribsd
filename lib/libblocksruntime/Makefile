# $FreeBSD$

PACKAGE=lib${LIB:tl}
LIB=	BlocksRuntime
SHLIB_MAJOR=0
CFLAGS+=-I${.CURDIR}
WARNS?=	2

.PATH: ${SRCTOP}/contrib/compiler-rt/lib/BlocksRuntime

INCS=	Block.h Block_private.h
SRCS=	data.c runtime.c

.ifdef LIBCHERI
CFLAGS+=	-Wno-error-mips-cheri-bugs
.endif

.include <bsd.lib.mk>
