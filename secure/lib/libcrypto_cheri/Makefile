# $FreeBSD$

NO_ENGINES=	yes

.include "../libcrypto/Makefile"

CFLAGS+=	-DLIBSSL_INSIDE_COMPARTMENT

NEED_CHERI=	sandbox

NO_SHARED=	yes

.PATH:	${.CURDIR}/../libcrypto
