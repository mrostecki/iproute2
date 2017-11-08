#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"
#include "bpf_util.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... bpf\n");
}

struct bpf_sch_req {
	struct nlmsghdr *n;
	int parms_type;
	int len;
};

static void bpf_sch_cb(void *raw, int fd, const char *annotation)
{
	struct bpf_sch_req *sch = raw;
	struct rtattr *parms;

	parms = addattr_nest(sch->n, sch->len, sch->parms_type);
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
	struct bpf_sch_req sch = {
		.len	= 1024,
		.n	= n,
	};
	struct bpf_cfg_in cfg = {
		.argc	= argc,
		.argv	= argv,
	};

	if (!argc)
		return 0;

	tail = NLMSG_TAIL(sch.n);
        addattr_l(sch.n, sch.len, TCA_OPTIONS, NULL, 0);
	sch.parms_type = TCA_BPF_PARMS_INGRESS;
	if (bpf_parse_common(BPF_PROG_TYPE_SCHED_CLS, &cfg, &bpf_cb_ops, &sch))
		return -1;

	tail->rta_len = (void *)NLMSG_TAIL(sch.n) - (void *)tail;
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
