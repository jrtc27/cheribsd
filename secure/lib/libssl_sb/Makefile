# $FreeBSD$

.if !defined(LSSL_SRC)
LSSL_SRC=	${SRCTOP}/secure/lib/libssl
.endif

COMPARTMENT_NAME=	ssl
SHLIB_MAJOR=	8

LDFLAGS+=	-Wl,-T,${SRCTOP}/lib/libc_cheri/sandbox.ld \
		-nostdlib -Wl,-error-limit=0 -v -Wl,-v

BINDIR=		/usr/libcheri

PROG=		${COMPARTMENT_NAME}.co.${SHLIB_MAJOR}

NO_LINT=

.if exists(${LSSL_SRC}/Makefile.man)
.include "${LSSL_SRC}/Makefile.man"
.endif
.include "../libcrypto/Makefile.inc"

SRCS=	bio_ssl.c d1_both.c d1_clnt.c d1_lib.c d1_meth.c d1_pkt.c d1_srtp.c \
	d1_srvr.c s23_clnt.c s23_lib.c s23_meth.c s23_pkt.c s23_srvr.c \
	s3_both.c s3_cbc.c s3_clnt.c s3_enc.c s3_lib.c s3_meth.c s3_pkt.c \
	s3_srvr.c ssl_algs.c ssl_asn1.c ssl_cert.c ssl_ciph.c ssl_conf.c \
	ssl_err.c ssl_err2.c ssl_lib.c ssl_rsa.c ssl_sess.c ssl_stat.c \
	ssl_txt.c t1_clnt.c t1_enc.c t1_ext.c t1_lib.c t1_meth.c t1_reneg.c \
	t1_srvr.c tls_srp.c ssl_sb.c

INCS=	dtls1.h kssl.h srtp.h ssl.h ssl2.h ssl23.h ssl3.h tls1.h
INCSDIR=${INCLUDEDIR}/openssl

LIBADD=	c_cheri crypto_cheri

CFLAGS+=	-I${LCRYPTO_SRC}/crypto
CFLAGS+=	-DLIBSSL_INSIDE_COMPARTMENT

NEED_CHERI=	sandbox
WANT_DUMP=	yes

NO_SHARED=	yes

.include <bsd.prog.mk>

.PATH:	${LCRYPTO_SRC}/ssl \
	${LSSL_SRC} \
	${.CURDIR}/man
