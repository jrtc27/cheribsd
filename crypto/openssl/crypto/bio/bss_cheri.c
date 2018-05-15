/* crypto/bio/bss_cheri.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_BSS_CHERI_C
# define HEADER_BSS_CHERI_C

# if defined(__linux) || defined(__sun) || defined(__hpux)
/*
 * Following definition aliases fopen to fopen64 on above mentioned
 * platforms. This makes it possible to open and sequentially access files
 * larger than 2GB from 32-bit application. It does not allow to traverse
 * them beyond 2GB with fseek/ftell, but on the other hand *no* 32-bit
 * platform permits that, not with fseek/ftell. Not to mention that breaking
 * 2GB limit for seeking would require surgery to *our* API. But sequential
 * access suffices for practical cases when you can run into large files,
 * such as fingerprinting, so we can let API alone. For reference, the list
 * of 32-bit platforms which allow for sequential access of large files
 * without extra "magic" comprise *BSD, Darwin, IRIX...
 */
#  ifndef _FILE_OFFSET_BITS
#   define _FILE_OFFSET_BITS 64
#  endif
# endif

# include <errno.h>
# include "cryptlib.h"
# include "bio_lcl.h"
# include <openssl/err.h>

# include <cheri/libcheri_fd.h>

static int MS_CALLBACK cheri_write(BIO *h, const char *buf, int num);
static int MS_CALLBACK cheri_read(BIO *h, char *buf, int size);
static int MS_CALLBACK cheri_puts(BIO *h, const char *str);
static int MS_CALLBACK cheri_gets(BIO *h, char *str, int size);
static long MS_CALLBACK cheri_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int MS_CALLBACK cheri_new(BIO *h);
static int MS_CALLBACK cheri_free(BIO *data);
static BIO_METHOD methods_cheri = {
    BIO_TYPE_CHERI,
    "CHERI object",
    cheri_write,
    cheri_read,
    cheri_puts,
    cheri_gets,
    cheri_ctrl,
    cheri_new,
    cheri_free,
    NULL,
};

BIO *BIO_new_cheri(struct cheri_object file, int close_flag)
{
    BIO *ret;

    if ((ret = BIO_new(BIO_s_cheri())) == NULL)
        return (NULL);

    BIO_set_cheri(ret, &file, close_flag);
    return (ret);
}

BIO_METHOD *BIO_s_cheri(void)
{
    return (&methods_cheri);
}

static int MS_CALLBACK cheri_new(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    memset(&bi->obj, 0, sizeof(struct cheri_object));
    bi->flags = 0;
    return (1);
}

static int MS_CALLBACK cheri_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            memset(&a->obj, 0, sizeof(struct cheri_object));
        }
        a->flags = 0;
        a->init = 0;
    }
    return (1);
}

static int MS_CALLBACK cheri_read(BIO *b, char *out, int outl)
{
    struct libcheri_fd_ret ret = {0, 0};

    if (b->init && (out != NULL)) {
        ret = libcheri_fd_read_c(b->obj, out, (size_t)outl);
        if (fd_ret.lcfr_retval0 == 0) {
            BIO_set_flags(b, BIO_FLAGS_EOF);
            break;
        } else if (ret.lcfr_retval0 < 0) {
            SYSerr(SYS_F_FREAD, ret.lcfr_retval1);
            BIOerr(BIO_F_CHERI_READ, ERR_R_SYS_LIB);
        }
    }
    return (ret.lcfr_retval0);
}

static int MS_CALLBACK cheri_write(BIO *b, const char *in, int inl)
{
    struct libcheri_fd_ret ret = {0, 0};

    if (b->init && (in != NULL)) {
        ret = libcheri_fd_write_c(b->obj, in, (size_t)inl);
        if (ret.lcfr_retval0)
            ret.lcfr_retval0 = inl;
    }
    return (ret.lcfr_retval0);
}

static long MS_CALLBACK cheri_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    struct libcheri_fd_ret fd_ret;
    long ret = 1;
    struct cheri_object file = b->obj;
    struct cheri_object *cp;
    char p[4];
    int st;

    switch (cmd) {
    case BIO_C_FILE_SEEK:
    case BIO_CTRL_RESET:
        fd_ret = libcheri_fd_lseek_c(file, num, 0).lcfr_retval0;
        ret = fd_ret.lcfr_retval0;
        break;
    case BIO_CTRL_EOF:
        ret = (b->flags & BIO_FLAGS_EOF) != 0;
        break;
    case BIO_C_FILE_TELL:
    case BIO_CTRL_INFO:
        /* TODO */
        ret = 0;
        break;
    case BIO_C_SET_CHERI_FILE:
        cheri_free(b);
        b->shutdown = (int)num & BIO_CLOSE;
        cp = (struct cheri_object *)ptr;
        b->obj = *cp;
        b->init = 1;
        BIO_clear_flags(b, BIO_FLAGS_EOF);
        break;
    case BIO_C_GET_CHERI_FILE:
        if (ptr != NULL) {
            cp = (struct cheri_object *)ptr;
            *cp = file;
        }
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = (long)b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_FLUSH:
        ret = 0;
        break;
    case BIO_CTRL_DUP:
        ret = 1;
        break;

    case BIO_CTRL_WPENDING:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int MS_CALLBACK cheri_gets(BIO *bp, char *buf, int size)
{
    int i;
    struct libcheri_fd_ret ret = {0, 0};

    for (i = 0; i < size - 1; i++) {
        ret = libcheri_fd_read_c(b->obj, buf+i, 1);
        if (fd_ret.lcfr_retval0 == 0) {
            BIO_set_flags(b, BIO_FLAGS_EOF);
            break;
        } else if (ret.lcfr_retval0 < 0) {
            break;
        }
        if (buf[i] == '\n') {
            i++;
            break;
        }
    }

    buf[i] = '\0';
    return (i);
}

static int MS_CALLBACK cheri_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = cheri_write(bp, str, n);
    return (ret);
}

#endif                          /* HEADER_BSS_CHERI_C */
