/*-
 * Copyright (c) 2014 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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

#ifndef	_VMM_IOPORT_H_
#define	_VMM_IOPORT_H_

#define VMM_IOPORT_REG_HANDLER

#ifdef VMM_IOPORT_REG_HANDLER
#define IOPORT_MAX_REG_HANDLER	12
struct ioport_reg_handler;
typedef int (*ioport_reg_handler_func_t)(struct vm *vm, struct ioport_reg_handler *vregh);
struct ioport_reg_handler {
	uint16_t port;
	int match_data;
	uint32_t data;
	ioport_reg_handler_func_t handler;
	void *handler_arg;
};

int
vmm_ioport_reg_handler(struct vm *vm, uint16_t port, int match_data, uint32_t data,
	int type, void *arg);
#endif /* VMM_IOPORT_HANDLER */

typedef int (*ioport_handler_func_t)(struct vm *vm, int vcpuid,
    bool in, int port, int bytes, uint32_t *val);

int vm_handle_inout(struct vm *vm, int vcpuid, struct vm_exit *vme, bool *retu);

#endif	/* _VMM_IOPORT_H_ */
