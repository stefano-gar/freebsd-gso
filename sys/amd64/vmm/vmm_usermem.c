/*
 * Copyright (C) 2015 Stefano Garzarella (stefano.garzarella@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sglist.h>
#include <sys/lock.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <machine/md_var.h>

#include "vmm_usermem.h"

#define MAX_USERMEMS	64

static struct usermem {
	struct vm       *vm;                    /* owner of this device */
	vm_paddr_t	gpa;
	size_t		len;
} usermems[MAX_USERMEMS];

int
vmm_usermem_add(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	int i;

	for (i = 0; i < MAX_USERMEMS; i++) {
		if (usermems[i].len == 0) {
			usermems[i].vm = vm;
			usermems[i].gpa = gpa;
			usermems[i].len = len;
			break;
		}
	}

	if (i == MAX_USERMEMS) {
		printf("vmm_usermem_add: empty usermem slot not found\n");
		return (ENOMEM);
	}

	return 0;
}

void
vmm_usermem_del(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	int i;

	for (i = 0; i < MAX_USERMEMS; i++) {
		if (usermems[i].vm == vm && usermems[i].gpa == gpa
				&& usermems[i].len == len) {
			bzero(&usermems[i], sizeof(struct usermem));
		}
	}
}

boolean_t
usermem_is_mmio(struct vm *vm, vm_paddr_t gpa)
{
	int i;

	for (i = 0; i < MAX_USERMEMS; i++) {
		if (usermems[i].vm != vm || usermems[i].len == 0)
			continue;
		if (gpa >= usermems[i].gpa &&
				gpa < usermems[i].gpa + usermems[i].len)
			return (TRUE);
	}
	return (FALSE);
}
