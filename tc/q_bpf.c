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
	struct bpf_sch_req *req = raw;
	struct rtattr *parms;

	parms = addattr_nest(req->n, req->len, req->parms_type);
	if (req->flags)
		addattr32(req->n, MAX_MSG, TCA_BPF_PARMS_FLAGS, req->flags);
	addattr32(req->n, MAX_MSG, TCA_BPF_PARMS_PROG, fd);
	addattr_nest_end(req->n, parms);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.ebpf_cb = bpf_sch_cb,
};

static int bpf_parse_prog(struct bpf_sch_req *req, int *argc, char ***argv,
			  int parms_type)
{
	struct bpf_cfg_in cfg = {
		.argc = *argc,
		.argv = *argv,
	};

	req->parms_type = parms_type;
	if (bpf_parse_common(BPF_PROG_TYPE_SCHED_CLS, &cfg, &bpf_cb_ops,
			     req))
		return -1;

	*argc = cfg.argc;
	*argv = cfg.argv;
	return 0;
}

static int bpf_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	bool probe_ok = true;
	struct rtattr *tail;
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
	if (matches(*argv, "ingress") == 0) {
		NEXT_ARG();
		if (bpf_parse_prog(&req, &argc, &argv, TCA_BPF_PARMS_INGRESS))
			return -1;
		probe_ok = NEXT_ARG_OK();
		if (probe_ok)
			NEXT_ARG_FWD();
	}
	if (probe_ok && matches(*argv, "egress") == 0) {
		NEXT_ARG();
		req.flags = 0;
		if (bpf_parse_prog(&req, &argc, &argv, TCA_BPF_PARMS_EGRESS))
			return -1;
		if (NEXT_ARG_OK())
			NEXT_ARG_FWD();
	}
	tail->rta_len = (void *)NLMSG_TAIL(req.n) - (void *)tail;
	return 0;
}

static void bpf_dump_prog(FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_BPF_PARMS_MAX + 1];
	uint32_t flags;

	parse_rtattr_nested(tb, TCA_BPF_PARMS_MAX, opt);
	if (tb[TCA_BPF_PARMS_FLAGS]) {
		flags = rta_getattr_u32(tb[TCA_BPF_PARMS_FLAGS]);
		if (flags & TCA_BPF_SCH_OFFLOAD)
			fprintf(f, "hw ");
	}
	if (tb[TCA_BPF_PARMS_PROG])
		bpf_dump_prog_info(f, rta_getattr_u32(tb[TCA_BPF_PARMS_PROG]));
}

static int bpf_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_BPF_SCH_MAX + 1];

	parse_rtattr_nested(tb, TCA_BPF_SCH_MAX, opt);
	if (tb[TCA_BPF_PARMS_INGRESS]) {
		fprintf(f, "\n ingress ");
		bpf_dump_prog(f, tb[TCA_BPF_PARMS_INGRESS]);
	}
	if (tb[TCA_BPF_PARMS_EGRESS]) {
		fprintf(f, "\n egress  ");
		bpf_dump_prog(f, tb[TCA_BPF_PARMS_EGRESS]);
	}
	fflush(f);
	return 0;
}

struct qdisc_util bpf_qdisc_util = {
	.id		= "bpf",
	.parse_qopt	= bpf_parse_opt,
	.print_qopt	= bpf_print_opt,
};
