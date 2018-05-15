# $FreeBSD$

LIB=		crypto_cheri

NO_ENGINES=	yes
LCRYPTO_CHERI=	yes

NEED_CHERI=	sandbox

NO_SHARED=	yes

.include "../libcrypto/Makefile"

CFLAGS+=	-DLIBSSL_INSIDE_COMPARTMENT

.PATH:	${.CURDIR}/../libcrypto
