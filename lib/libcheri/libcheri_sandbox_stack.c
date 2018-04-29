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

#include <sys/types.h>
#include <sys/mman.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <assert.h>
#include <err.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include "libcheri_sandbox.h"
#include "libcheri_sandbox_internal.h"
#include "libcheri_sandbox_stack.h"

struct sandbox_object_list_node
{
	struct sandbox_object *sbop;
	struct sandbox_object_list_node *next;
};

static struct sandbox_object_list_node *sbo_list_head;

/* Element 0: chain double pointer */
__thread struct libcheri_thread_stacks_info __libcheri_sandbox_stacks;

static struct libcheri_thread_stacks_info * __capability stacks_list_head;
static struct libcheri_thread_stacks_info * __capability *stacks_list_tail = &stacks_list_head;

static unsigned int allocated_stack_slots = 4;

static pthread_mutex_t global_lock;

static void libcheri_sandbox_stack_register_stacks(struct libcheri_thread_stacks_info *stacksp)
{
	*stacks_list_tail =
		(__cheri_tocap struct libcheri_thread_stacks_info * __capability)
		stacksp;
	stacks_list_tail =
		(__cheri_fromcap struct libcheri_thread_stacks_info * __capability *)
		stacksp->stacks;
}

static void libcheri_sandbox_stack_realloc(struct libcheri_thread_stacks_info *stacksp)
{
	bool update_tail = stacks_list_tail ==
		(__cheri_fromcap struct libcheri_thread_stacks_info * __capability *)
		stacksp->stacks;
	stacksp->stacks =
		(__cheri_tocap void * __capability * __capability)
		realloc((__cheri_fromcap void *)stacksp->stacks,
			allocated_stack_slots*sizeof(void * __capability));
	if (update_tail) {
		stacks_list_tail =
			(__cheri_fromcap struct libcheri_thread_stacks_info * __capability *)
			stacksp->stacks;
	}
}

void libcheri_sandbox_stack_init(void)
{
	libcheri_sandbox_stack_realloc(&__libcheri_sandbox_stacks);
	libcheri_sandbox_stack_register_stacks(&__libcheri_sandbox_stacks);
}

void libcheri_sandbox_stack_thread_started(void)
{
	struct sandbox_object_list_node *node;
	unsigned int stackidx;

	pthread_mutex_lock(&global_lock);
	libcheri_sandbox_stack_realloc(&__libcheri_sandbox_stacks);
	for (node = sbo_list_head; node; node = node->next) {
		stackidx = node->sbop->sbo_stackoff / sizeof(void * __capability);
		__libcheri_sandbox_stacks.stacks[stackidx] =
			(__cheri_tocap void * __capability)
			mmap(0, node->sbop->sbo_stacklen,
				PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	}
	libcheri_sandbox_stack_register_stacks(&__libcheri_sandbox_stacks);
	pthread_mutex_unlock(&global_lock);
}

void libcheri_sandbox_stack_thread_stopped(void)
{
	struct sandbox_object_list_node *node;
	unsigned int stackidx;

	pthread_mutex_lock(&global_lock);
	libcheri_sandbox_stack_realloc(&__libcheri_sandbox_stacks);
	for (node = sbo_list_head; node; node = node->next) {
		stackidx = node->sbop->sbo_stackoff / sizeof(void * __capability);
		munmap((__cheri_fromcap void *)
			__libcheri_sandbox_stacks.stacks[stackidx],
			node->sbop->sbo_stacklen);
	}
	libcheri_sandbox_stack_register_stacks(&__libcheri_sandbox_stacks);
	pthread_mutex_unlock(&global_lock);
}

void libcheri_sandbox_stack_sandbox_created(struct sandbox_object *sbop)
{
	struct libcheri_thread_stacks_info * __capability stacksp;
	struct sandbox_object_list_node *node, *curr, *prev;
	int unlocked = 0;
	unsigned int stackidx;
	bool need_realloc;
	void *stackmem;

	node = malloc(sizeof(*node));
	node->sbop = sbop;

	pthread_mutex_lock(&global_lock);

	for (prev = NULL, curr = sbo_list_head; curr; prev = curr, curr = curr->next) {
		if (prev) {
			if (prev->sbop->sbo_stackoff+sizeof(void * __capability)
			    != curr->sbop->sbo_stackoff) {
				break;
			}
		} else {
			if (curr->sbop->sbo_stackoff
			    != sizeof(void * __capability)) {
				break;
			}
		}
	}

	if (!prev) {
		stackidx = 1;
		node->next = sbo_list_head;
		sbo_list_head = node;
	} else {
		stackidx = prev->sbop->sbo_stackoff/sizeof(void * __capability) + 1;
		node->next = prev->next;
		prev->next = node;
	}

	sbop->sbo_stackoff = stackidx*sizeof(void * __capability);

	need_realloc = stackidx == allocated_stack_slots;
	if (need_realloc) {
		allocated_stack_slots *= 2;
	}

	for (stacksp = stacks_list_head; stacksp; stacksp = stacksp->stacks[0]) {
		if (need_realloc) {
			while (!atomic_compare_exchange_weak_explicit(
					&stacksp->lock, &unlocked, 1,
					memory_order_acquire,
					memory_order_relaxed)) {
				while (atomic_load_explicit(&stacksp->lock,
						memory_order_relaxed))
					;
			}

			libcheri_sandbox_stack_realloc(
				(__cheri_fromcap struct libcheri_thread_stacks_info *)
				stacksp);

			atomic_store_explicit(&stacksp->lock, 0,
				memory_order_release);
		}

			mmap(0, sbop->sbo_stacklen,
				PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);

		/*
		 * Note that the capability is local (can't be shared) and can
		 * store local pointers (i.e., further stack-derived
		 * capabilities such as return addresses).
		 * XXX-JC: Made global since foo(&stackvar) is far too common,
		 * and libcheri_system_calloc is a pain.
		 */
		stacksp->stacks[stackidx] = cheri_ptrperm(stackmem,
		    sbop->sbo_stacklen, CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
		    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		    CHERI_PERM_STORE_LOCAL_CAP);
	}

	pthread_mutex_unlock(&global_lock);
}

void libcheri_sandbox_stack_sandbox_destroyed(struct sandbox_object *sbop)
{
	struct libcheri_thread_stacks_info * __capability stacksp;
	struct sandbox_object_list_node *node;
	struct sandbox_object_list_node **inptr;
	unsigned int stackidx;

	pthread_mutex_lock(&global_lock);

	for (node = sbo_list_head, inptr = &sbo_list_head;
	     node && node->sbop != sbop;
	     inptr = &node->next, node = node->next)
		;

	assert(node);

	*inptr = node->next;

	stackidx = sbop->sbo_stackoff / sizeof(void * __capability);
	for (stacksp = stacks_list_head; stacksp; stacksp = stacksp->stacks[0]) {
		munmap((__cheri_fromcap void *)stacksp->stacks[stackidx],
			sbop->sbo_stacklen);
		stacksp->stacks[stackidx] = NULL;
	}

	pthread_mutex_unlock(&global_lock);

	free(node);
}

int
libcheri_sandbox_stack_reset_stack(struct sandbox_object *sbop)
{
	struct libcheri_thread_stacks_info * __capability stacksp;
	int unlocked = 0;
	unsigned int stackidx;
	void *stackmem;
	int err;

	stackidx = sbop->sbo_stackoff / sizeof(void * __capability);

	pthread_mutex_lock(&global_lock);

	for (stacksp = stacks_list_head; stacksp && !err; stacksp = stacksp->stacks[0]) {
		while (!atomic_compare_exchange_weak_explicit(
				&stacksp->lock, &unlocked, 1,
				memory_order_acquire,
				memory_order_relaxed)) {
			while (atomic_load_explicit(&stacksp->lock,
					memory_order_relaxed))
				;
		}

		stackmem = (__cheri_fromcap void *)stacksp->stacks[stackidx];
		if (mmap(stackmem, sbop->sbo_stacklen,
		    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0) ==
		    MAP_FAILED) {
			warn("%s: stack reset", __func__);
			err = -1;
		}

		atomic_store_explicit(&stacksp->lock, 0,
			memory_order_release);
	}

	pthread_mutex_unlock(&global_lock);

	return (err);
}
