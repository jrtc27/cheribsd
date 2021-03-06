# $FreeBSD$

# Use the following command to build local debug version of dynamic
# linker:
# make DEBUG_FLAGS=-g DEBUG=-DDEBUG WITHOUT_TESTS=yes all

.include <src.opts.mk>
MK_SSP=		no
MK_CHERI_SHARED_PROG:=yes

.PATH: ${.CURDIR}/../../lib/libmalloc_simple

# TODO: disable this once we believe RTLD works reliably
DEBUG=-DDEBUG

PROG?=		ld-cheri-elf.so.1
SRCS=		rtld_start.S \
		reloc.c rtld.c rtld_lock.c map_object.c \
		heap.c malloc.c xmalloc.c debug.c libmap.c
MAN=
NEED_CHERI=	pure
WANT_DUMP=yes
MK_CHERI_SHARED=yes
CSTD?=		gnu99
CFLAGS+=	-Wall -DFREEBSD_ELF -DIN_RTLD -ffreestanding
CFLAGS+=	-I${SRCTOP}/lib/csu/common \
		-I${SRCTOP}/lib/libc/${RTLD_ARCH}
.if exists(${.CURDIR}/${MACHINE_ARCH})
RTLD_ARCH=	${MACHINE_ARCH}
.else
RTLD_ARCH=	${MACHINE_CPUARCH}
.endif
CFLAGS+=	-I${.CURDIR}/${RTLD_ARCH} -I${.CURDIR}
LDFLAGS+=	-nostdlib -e rtld_start
WARNS?=		2
INSTALLFLAGS=	-C -b
PRECIOUSPROG=
BINDIR=		/libexec
#SYMLINKS=	${BINDIR}/${PROG} ${LIBEXECDIR}/${PROG}

CFLAGS+=	-fpic
CFLAGS+=	-DPIC $(DEBUG)
CFLAGS.reloc.c+=-fno-jump-tables
LDFLAGS+=	-shared -Wl,-Bsymbolic -Wl,-z,defs
# avoid accidentally depending on non-existent symbols
LDFLAGS+=	-Wl,-no-undefined
LIBADD=		c_pic

# For floating-point functions used by gdtoa.
LIBADD+=	compiler_rt

# for the rtld_printf functions:
SIMPLE_PRINTF_PREFIX=rtld
.include "${SRCTOP}/lib/libsimple_printf/Makefile.inc"

.if ${MK_SYMVER} == "yes"
# LIBCSRCDIR does not appear to be set correctly for libcheribuildenv
LIBCSRCDIR=	${SRCTOP}/lib/libc
VERSION_DEF=	${LIBCSRCDIR}/Versions.def
SYMBOL_MAPS=	${.CURDIR}/../rtld-elf/Symbol.map
VERSION_MAP=	Version.map
LDFLAGS+=	-Wl,--version-script=${VERSION_MAP}

.if exists(${.CURDIR}/${RTLD_ARCH}/Symbol.map)
SYMBOL_MAPS+=	${.CURDIR}/${RTLD_ARCH}/Symbol.map
.endif
.endif

#.sinclude "${.CURDIR}/${RTLD_ARCH}/Makefile.inc"

.PATH: ${.CURDIR}/${RTLD_ARCH}

.include <bsd.prog.mk>
${PROG_FULL}:	${VERSION_MAP}
.include <bsd.symver.mk>

#CFLAGS:=	${CFLAGS} -O0
