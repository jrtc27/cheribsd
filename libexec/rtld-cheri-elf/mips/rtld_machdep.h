/*-
 * Copyright (c) 1999, 2000 John D. Polstra.
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#ifndef RTLD_MACHDEP_H
#define RTLD_MACHDEP_H	1

#include <sys/types.h>
#include <machine/atomic.h>
#include <machine/tls.h>

#include <cheri.h>

struct Struct_Obj_Entry;

uintcap_t set_cp(struct Struct_Obj_Entry *obj);

/* Return the address of the .dynamic section in the dynamic linker. */
#define rtld_dynamic(obj) (&_DYNAMIC)

Elf_Addr reloc_jmpslot(Elf_Addr *where, Elf_Addr target,
		       const struct Struct_Obj_Entry *defobj,
		       const struct Struct_Obj_Entry *obj,
		       const Elf_Rel *rel);

struct fdesc {
	uintcap_t pcc;
	uintcap_t cp;
};

#define ptr_to_fdesc(_ptr)						\
({									\
	union {								\
		void *ptr;						\
		struct fdesc *fdesc;					\
	} u;								\
	u.ptr = _ptr;							\
	u.fdesc;							\
})

#define fdesc_to_ptr(_fdesc)						\
({									\
	union {								\
		void *ptr;						\
		struct fdesc *fdesc;					\
	} u;								\
	u.fdesc = _fdesc;						\
	u.ptr;								\
})

#define make_function_pointer(def, defobj)				\
	((defobj)->relocbase + (def)->st_value)

#define make_entry_function_pointer(entry, obj_main, fdesc_out)		\
({									\
	(fdesc_out)->pcc = (uintcap_t)(entry);				\
	(fdesc_out)->cp = (obj_main)->cp;				\
	fdesc_to_ptr(fdesc_out);					\
})

//#define call_initfini_pointer(obj, target)				\
//	(((InitFunc)(cheri_setoffset(cheri_getpcc(), (target))))())
//
//#define call_init_pointer(obj, target)					\
//	(((InitArrFunc)(cheri_setoffset(cheri_getpcc(), (target))))	\
//	    (main_argc, main_argv, environ))

#define call_initfini_pointer(obj, target)				\
({									\
	uintcap_t old0;							\
	old0 = set_cp(obj);						\
	(((InitFunc)(cheri_setoffset(cheri_getpcc(), (target))))());	\
	__asm__ __volatile__ ("cmove	$c14, %0" :: "C"(old0));	\
})

#define call_init_pointer(obj, target)					\
({									\
	uintcap_t old1;							\
	old1 = set_cp(obj);						\
	(((InitArrFunc)(cheri_setoffset(cheri_getpcc(), (target))))	\
	    (main_argc, main_argv, environ));				\
	__asm__ __volatile__ ("cmove	$c14, %0" :: "C"(old1));	\
})

#define	call_ifunc_resolver(ptr) \
	(((Elf_Addr (*)(void))ptr)())

typedef struct {
	unsigned long ti_module;
	unsigned long ti_offset;
} tls_index;

#define round(size, align) \
    (((size) + (align) - 1) & ~((align) - 1))
#define calculate_first_tls_offset(size, align) \
    round(TLS_TCB_SIZE, align)
#define calculate_tls_offset(prev_offset, prev_size, size, align) \
    round(prev_offset + prev_size, align)
#define calculate_tls_end(off, size)    ((off) + (size))

/*
 * Lazy binding entry point, called via PLT.
 */
void _rtld_bind_start(void);

extern void *__tls_get_addr(tls_index *ti);

#define	RTLD_DEFAULT_STACK_PF_EXEC	PF_X
#define	RTLD_DEFAULT_STACK_EXEC		PROT_EXEC

#define md_abi_variant_hook(x)

#endif
