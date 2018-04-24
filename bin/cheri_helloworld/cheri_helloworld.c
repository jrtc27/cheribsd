/*-
 * Copyright (c) 2014-2017 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 */

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/libcheri_async.h>
#include <cheri/libcheri_fd.h>
#include <cheri/libcheri_sandbox.h>
#include <cheri/helloworld.h>

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <sysexits.h>
#include <unistd.h>

#include <pthread.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int received_callback;
static void *received_arg;
static int received_err;

static void
helloworld_cb(void * __capability arg, int err /*, retval */)
{
	puts("hello world callback");
	pthread_mutex_lock(&lock);
	received_callback = 1;
	received_arg = (__cheri_fromcap void *)arg;
	received_err = err;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
}

int
main(void)
{
	struct sandbox_object *sbop;
	int ret;
	struct cheri_object stdout_fd;
	struct libcheri_message msg;
	struct libcheri_callback cb;
	int dummy_arg;

	libcheri_init();

	if (libcheri_fd_new(STDOUT_FILENO, &sbop) < 0)
		err(EX_OSFILE, "libcheri_fd_new: stdout");

	ret = call_libcheri_system_helloworld();
	assert(ret == 123456);

	ret = call_libcheri_system_puts();
	assert(ret >= 0);

	stdout_fd = sandbox_object_getobject(sbop);
	ret = call_libcheri_fd_write_c(stdout_fd);
	assert(ret == 12);

	cb.func = (__cheri_tocap void (*)(void * __capability, int))helloworld_cb;
	cb.arg = (__cheri_tocap void *)&dummy_arg;
	msg.method_num = system_puts_method_num;
	msg.callback = (__cheri_tocap struct libcheri_callback *)&cb;
	msg.rcv_ring = libcheri_async_get_ring();
	libcheri_message_send(__helloworld_objectp, &msg);

	pthread_mutex_lock(&lock);
	while (!received_callback)
		pthread_cond_wait(&cond, &lock);
	pthread_mutex_unlock(&lock);

	assert(received_arg == &dummy_arg);
	assert(received_err >= 0);

	libcheri_fd_destroy(sbop);

	return (0);
}
