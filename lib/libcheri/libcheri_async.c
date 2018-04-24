/*-
 * Copyright (c) 2017 Robert N. M. Watson
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

#include <sys/types.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <err.h>
#include <stdlib.h>

#include <pthread.h>

#include "libcheri_async.h"
#include "libcheri_init.h"
#include "libcheri_invoke.h"
#include "libcheri_sandbox_internal.h"

enum libcheri_ring_message_type
{
	libcheri_ring_message_request,
	libcheri_ring_message_response
};

struct libcheri_ring_message
{
	enum libcheri_ring_message_type type;
	struct libcheri_message msg;
};

#define RING_BUFSZ 1024

struct libcheri_ring
{
	struct sandbox_object *sbop;
	struct libcheri_ring_message buf[RING_BUFSZ];
	size_t head, tail, count;
	pthread_mutex_t lock;
	pthread_cond_t cond_enqueue;
	pthread_cond_t cond_dequeue;
};

static struct libcheri_ring program_ring = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.cond_enqueue = PTHREAD_COND_INITIALIZER,
	.cond_dequeue = PTHREAD_COND_INITIALIZER
};

static pthread_attr_t worker_attr;

void
libcheri_message_send(struct sandbox_object *sbop,
    struct libcheri_message *req)
{
	struct libcheri_ring *ringp =
		(__cheri_fromcap struct libcheri_ring *)sbop->sbo_ring;
	libcheri_async_enqueue_request_unsealed(ringp, req);
}

void
libcheri_async_enqueue_request(struct libcheri_ring * __capability ring,
    struct libcheri_message *req)
{
	struct libcheri_ring *ringp =
		(__cheri_fromcap struct libcheri_ring *)cheri_unseal(ring, libcheri_ring_type);
	libcheri_async_enqueue_request_unsealed(ringp, req);
}

void
libcheri_async_enqueue_response(struct libcheri_ring * __capability ring,
    struct libcheri_message *resp)
{
	struct libcheri_ring *ringp =
		(__cheri_fromcap struct libcheri_ring *)cheri_unseal(ring, libcheri_ring_type);
	libcheri_async_enqueue_response_unsealed(ringp, resp);
}

/* TODO: Avoid deadlock somehow */

void
libcheri_async_enqueue_request_unsealed(struct libcheri_ring *ring,
    struct libcheri_message *req)
{
	pthread_mutex_lock(&ring->lock);
	while (ring->head == ring->tail && ring->count != 0)
		pthread_cond_wait(&ring->cond_enqueue, &ring->lock);

	ring->buf[ring->tail].type = libcheri_ring_message_request;
	ring->buf[ring->tail].msg = *req;
	ring->tail = (ring->tail + 1) % RING_BUFSZ;
	++ring->count;
	pthread_cond_signal(&ring->cond_dequeue);
	pthread_mutex_unlock(&ring->lock);
}

void
libcheri_async_enqueue_response_unsealed(struct libcheri_ring *ring,
    struct libcheri_message *resp)
{
	pthread_mutex_lock(&ring->lock);
	while (ring->head == ring->tail && ring->count != 0)
		pthread_cond_wait(&ring->cond_enqueue, &ring->lock);

	ring->buf[ring->tail].type = libcheri_ring_message_response;
	ring->buf[ring->tail].msg = *resp;
	ring->tail = (ring->tail + 1) % RING_BUFSZ;
	++ring->count;
	pthread_cond_signal(&ring->cond_dequeue);
	pthread_mutex_unlock(&ring->lock);
}

static void *
libcheri_async_worker(void *arg)
{
	struct libcheri_ring *ring = (struct libcheri_ring *)arg;
	struct libcheri_ring_message msg;
	struct libcheri_message resp;
	int ret;

	for (;;) {
		pthread_mutex_lock(&ring->lock);
		while (ring->head == ring->tail && ring->count == 0)
			pthread_cond_wait(&ring->cond_dequeue, &ring->lock);

		--ring->count;
		msg = ring->buf[ring->head];
		ring->head = (ring->head + 1) % RING_BUFSZ;
		pthread_cond_signal(&ring->cond_enqueue);
		pthread_mutex_unlock(&ring->lock);

		if (msg.type == libcheri_ring_message_request) {
			ret = libcheri_invoke(ring->sbop->sbo_cheri_object_invoke,
			    msg.msg.method_num,
			    msg.msg.a0, msg.msg.a1, msg.msg.a2,
			    msg.msg.a3, msg.msg.a4, msg.msg.a5,
			    msg.msg.a6, msg.msg.a7,
			    msg.msg.c3, msg.msg.c4, msg.msg.c5,
			    msg.msg.c6, msg.msg.c7, msg.msg.c8,
			    msg.msg.c9, msg.msg.c10);

			resp.a1 = ret;
			resp.callback = msg.msg.callback;
			libcheri_async_enqueue_response(msg.msg.rcv_ring, &resp);
		} else {
			/* TODO: unseal */
			/* TODO: sandboxed callback */
			msg.msg.callback->func(msg.msg.callback->arg, msg.msg.a1);
		}
	}
	return (NULL);
}

void *
libcheri_async_alloc_ring(struct sandbox_object *sbop)
{
	struct libcheri_ring *ring = calloc(1, sizeof(*ring));
	if (ring == NULL) {
		warn("%s: calloc", __func__);
		return (NULL);
	}
	ring->sbop = sbop;
	ring->lock = PTHREAD_MUTEX_INITIALIZER;
	ring->cond_enqueue = PTHREAD_COND_INITIALIZER;
	ring->cond_dequeue = PTHREAD_COND_INITIALIZER;
	return (ring);
}

int
libcheri_async_start_worker(struct libcheri_ring *ring)
{
	pthread_t thread;
	int ret;

	ret = pthread_create(&thread, &worker_attr, libcheri_async_worker, ring);
	if (ret != 0)
		warn("%s: pthread_create", __func__);

	return (ret);
}

void
libcheri_async_init(void)
{
	int ret;

	ret = pthread_attr_init(&worker_attr);
	if (ret != 0)
		err(1, "%s: pthread_attr_init", __func__);

	ret = pthread_attr_setdetachstate(&worker_attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0)
		err(1, "%s: pthread_attr_setdetachstate", __func__);

	ret = libcheri_async_start_worker(&program_ring);
	if (ret != 0)
		err(1, "%s: libcheri_async_start_worker", __func__);
}

struct libcheri_ring * __capability
libcheri_async_get_ring(void)
{
	/* Called from the main application */
	return cheri_seal((__cheri_tocap struct libcheri_ring * __capability)&program_ring, libcheri_ring_type);
}
