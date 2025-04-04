
# regex sources
.PATH: ${LIBC_SRCTOP}/regex

CFLAGS+=-DPOSIX_MISTAKE

SRCS+=	regcomp.c regerror.c regexec.c regfree.c

SYM_MAPS+=${LIBC_SRCTOP}/regex/Symbol.map

# manpages only included in libc version
.if defined(LIB) && ${LIB} == "c"
MAN+=	regex.3
MAN+=	re_format.7

MLINKS+=regex.3 regcomp.3 regex.3 regexec.3 regex.3 regerror.3
MLINKS+=regexec.3 regfree.3
.endif
