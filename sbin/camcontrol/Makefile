# $FreeBSD$

# Requires CAMIOCOMMAND (uses union ccb)
WANT_CHERI=	none

PACKAGE=runtime
PROG=	camcontrol
SRCS=	camcontrol.c util.c
.if !defined(RELEASE_CRUNCH)
SRCS+=	attrib.c epc.c fwdownload.c modeedit.c persist.c progress.c timestamp.c zone.c
.else
CFLAGS+= -DMINIMALISTIC
.endif
# This is verboten
.if ${MACHINE_CPUARCH} == "arm"
WARNS?= 3
.endif
LIBADD=	cam sbuf util
MAN=	camcontrol.8

.include <bsd.prog.mk>
