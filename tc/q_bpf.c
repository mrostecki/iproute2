/*
 * q_bpf.c      BPF tc program loader
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"
#include "bpf_util.h"

struct bpf_sch_req {
	struct nlmsghdr *n;
	uint32_t flags;
	int parms_type;
	int len;
};

static void bpf_sch_cb(void *raw, int fd, const char *annotation)
{
	struct bpf_sch_req *sch = raw;
	struct rtattr *parms;

	parms = addattr_nest(sch->n, sch->len, sch->parms_type);
	if (sch->flags)
		addattr32(sch->n, MAX_MSG, TCA_BPF_PARMS_FLAGS, sch->flags);
	addattr32(sch->n, MAX_MSG, TCA_BPF_PARMS_PROG, fd);
	addattr_nest_end(sch->n, parms);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.ebpf_cb = bpf_sch_cb,
};

static int bpf_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	struct rtattr *tail;
	struct bpf_cfg_in cfg = { };
	struct bpf_sch_req req = {
		.len	= 1024,
		.n	= n,
	};

	if (!argc)
		return 0;
	if (strcmp(*argv, "hw") == 0) {
		req.flags |= TCA_BPF_SCH_OFFLOAD;
		NEXT_ARG();
	}
	tail = NLMSG_TAIL(req.n);
	addattr_l(req.n, req.len, TCA_OPTIONS, NULL, 0);
	if (strcmp(*argv, "ingress") == 0) {
		NEXT_ARG();
		cfg.argc = argc;
		cfg.argv = argv;
		req.parms_type = TCA_BPF_PARMS_INGRESS;
		if (bpf_parse_common(BPF_PROG_TYPE_SCHED_CLS, &cfg, &bpf_cb_ops,
				     &req))
			return -1;
		argc = cfg.argc;
		argv = cfg.argv;
		if (NEXT_ARG_OK())
			NEXT_ARG_FWD();
	}
	if (strcmp(*argv, "egress") == 0) {
		NEXT_ARG();
		req.flags = 0;
		cfg.argc = argc;
		cfg.argv = argv;
		req.parms_type = TCA_BPF_PARMS_EGRESS;
		if (bpf_parse_common(BPF_PROG_TYPE_SCHED_CLS, &cfg, &bpf_cb_ops,
				     &req))
			return -1;
		argc = cfg.argc;
		argv = cfg.argv;
		if (NEXT_ARG_OK())
			NEXT_ARG_FWD();
	}
	tail->rta_len = (void *)NLMSG_TAIL(req.n) - (void *)tail;
	return 0;
}

static int bpf_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	return 0;
}

struct qdisc_util bpf_qdisc_util = {
	.id		= "bpf",
	.parse_qopt	= bpf_parse_opt,
	.print_qopt	= bpf_print_opt,
};
