#
# All library objects contain FreeBSD revision strings by default; they may be
# excluded as a space-saving measure.  To produce a library that does
# not contain these strings, add -DSTRIP_FBSDID (see <sys/cdefs.h>) to CFLAGS
# below.

PACKAGE=	clibs
SHLIBDIR?= /lib

.include <src.opts.mk>
MK_SSP=	no

.if !defined(LIBTHR_SRCTOP)
LIBTHR_SRCTOP:=	${.PARSEDIR}
.endif
.PATH: ${LIBTHR_SRCTOP}

.ifdef RTLD_SANDBOX
SHLIB=thr
.else
LIB=thr
.endif
SHLIB_MAJOR= 3
NO_WTHREAD_SAFETY=1
NO_WCAST_ALIGN.gcc=1    # for gcc 4.2
CFLAGS+=-DPTHREAD_KERNEL
CFLAGS+=-I${SRCTOP}/lib/libc/include
CFLAGS+=-I${SRCTOP}/lib/libc/${MACHINE_CPUARCH}
CFLAGS+=-I${LIBTHR_SRCTOP}/thread
CFLAGS+=-I${LIBTHR_SRCTOP}/arch/${MACHINE_CPUARCH}/include
CFLAGS+=-I${LIBTHR_SRCTOP}/sys
CFLAGS+=-I${SRCTOP}/libexec/rtld-elf
CFLAGS+=-I${SRCTOP}/libexec/rtld-elf/${MACHINE_CPUARCH}
CFLAGS+=-I${SRCTOP}/lib/libthread_db

CFLAGS.thr_stack.c+=	-Wno-cast-align
CFLAGS.rtld_malloc.c+=	-Wno-cast-align
CFLAGS.thr_symbols.c+=	-Wno-missing-variable-declarations
.if ${MK_ASAN} != "no"
# False-positive ASAN error claiming the local "struct sigaction act;" is
# overflowed by handle_signal() reading from the ucontext_t argument. This
# could be caused by ASAN not treating this function as a signal handler.
CFLAGS.thr_sig.c+=	-fno-sanitize=address
.endif

.if ${MACHINE_CPUARCH} == "arm" || defined(RTLD_SANDBOX)
# XXX: RTLD_SANDBOX currently does not support stack unwinding.
NO_THREAD_UNWIND_STACK= yes
.endif

.ifndef NO_THREAD_UNWIND_STACK
CFLAGS+=-fexceptions
CFLAGS+=-D_PTHREAD_FORCED_UNWIND
.endif

.ifdef RTLD_SANDBOX
CFLAGS+=-DRTLD_SANDBOX
.endif

LDFLAGS+=-Wl,-znodelete

VERSION_DEF=${SRCTOP}/lib/libc/Versions.def
SYMBOL_MAPS=${LIBTHR_SRCTOP}/pthread.map

.ifndef RTLD_SANDBOX
MAN=	libthr.3
.endif

.if ${MK_PTHREADS_ASSERTIONS} != "no"
# enable extra internal consistency checks
CFLAGS+=-D_PTHREADS_INVARIANTS
.endif

PRECIOUSLIB=

.PATH: ${LIBTHR_SRCTOP}/arch/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}
.if ${MACHINE_ABI:Mpurecap}
.PATH: ${SRCTOP}/lib/libmalloc_simple
.else
.PATH: ${SRCTOP}/libexec/rtld-elf
.endif

.if exists(${LIBTHR_SRCTOP}/arch/${MACHINE_CPUARCH}/Makefile.inc)
.include "${LIBTHR_SRCTOP}/arch/${MACHINE_CPUARCH}/Makefile.inc"
.endif
.include "${LIBTHR_SRCTOP}/sys/Makefile.inc"
.include "${LIBTHR_SRCTOP}/thread/Makefile.inc"
.if ${MACHINE_ABI:Mpurecap}
SRCS+=	malloc.c heap.c
CFLAGS.malloc.c+=	-DIN_LIBTHR
CFLAGS.heap.c+=	-DIN_LIBTHR
.else
SRCS+= rtld_malloc.c
.endif

.ifndef RTLD_SANDBOX
.if ${MK_INSTALLLIB} != "no"
SYMLINKS+=lib${LIB}.a ${LIBDIR}/libpthread.a
.endif
.if !defined(NO_PIC)
SYMLINKS+=lib${LIB}.so ${LIBDIR}/libpthread.so
.endif
.if ${MK_PROFILE} != "no"
SYMLINKS+=lib${LIB}_p.a ${LIBDIR}/libpthread_p.a
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.endif

.include <bsd.lib.mk>
