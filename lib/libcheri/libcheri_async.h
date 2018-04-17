/*-
 * Copyright (c) 2018 James Clarke
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

#ifndef _LIBCHERI_ASYNC_H_
#define _LIBCHERI_ASYNC_H_

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

struct libcheri_ring;
struct sandbox_object;

struct libcheri_callback {
	void (* __capability func)(void * __capability , int /*, retval */);
	void * __capability arg;
};

struct libcheri_message {
	register_t method_num;

	register_t a0;
	register_t a1;
	register_t a2;
	register_t a3;
	register_t a4;
	register_t a5;
	register_t a6;
	register_t a7;

	__capability void *c3;
	__capability void *c4;
	__capability void *c5;
	__capability void *c6;
	__capability void *c7;
	__capability void *c8;
	__capability void *c9;
	__capability void *c10;

	struct libcheri_callback * __capability callback; /* sealed */
	struct libcheri_ring * __capability rcv_ring; /* sealed */
};

void
libcheri_message_send(struct sandbox_object *sbop,
    struct libcheri_message *req);

void
libcheri_async_enqueue_request(struct libcheri_ring *ring,
    struct libcheri_message *req);

void
libcheri_async_enqueue_response(struct libcheri_ring *ring,
    struct libcheri_message *resp);

void *
libcheri_async_alloc_ring(struct sandbox_object *sbop);

int
libcheri_async_start_worker(struct libcheri_ring *ring);

/* Provided by libcheri itself for the main application, and provided by
 * libc_cheri as a wrapper around libcheri_system_get_ring for compartments. */
struct libcheri_ring * __capability
libcheri_async_get_ring(void);

#endif /* !_LIBCHERI_ASYNC_H_ */
