#include "../../include/bpf_api.h"

struct bpf_elf_map __section_maps map_sh = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(uint32_t),
	.size_value	= sizeof(uint32_t),
	.pinning	= PIN_OBJECT_NS, /* or PIN_GLOBAL_NS, or PIN_NONE */
	.max_elem	= 1,
};

#define X__key(x)	printt("key" #x ": %x %x %x\n", (__u8)__key[(x)], (__u8)__key[(x+1)], (__u8)__key[(x+2)])
#define X__val(x)	printt("val" #x ": %x %x %x\n", (__u8)__val[(x)], (__u8)__val[(x+1)], (__u8)__val[(x+2)])

__section("kprobes/bpf_map_lookup_elem")
int probe1(struct pt_regs *ctx)
{
	__u8 *key, __key[80] = {};

	printt("bpf_map_lookup_elem\n");
	key = (__u8 *) PT_REGS_PARM2(ctx);
	bpf_probe_read(__key, sizeof(__key), key);
	X__key(0);
	X__key(3);
	X__key(6);
	X__key(9);
	X__key(12);
	X__key(15);
	X__key(18);
	X__key(21);
	X__key(24);
	X__key(27);
	X__key(30);

	return 0;
}

__section("kprobes/bpf_map_update_elem")
int probe2(struct pt_regs *ctx)
{
	__u8 *key, __key[80] = {}, *val, __val[80] = {};

	printt("bpf_map_update_elem\n");
	key = (__u8 *) PT_REGS_PARM2(ctx);
	bpf_probe_read(__key, sizeof(__key), key);
	X__key(0);
	X__key(3);
	X__key(6);
	X__key(9);
	X__key(12);
	X__key(15);
	X__key(18);
	X__key(21);
	X__key(24);
	X__key(27);
	X__key(30);

	val = (__u8 *) PT_REGS_PARM3(ctx);
	bpf_probe_read(__val, sizeof(__val), val);
	X__val(0);
	X__val(3);
	X__val(6);
	X__val(9);
	X__val(12);
	X__val(15);
	X__val(18);
	X__val(21);
	X__val(24);
	X__val(27);
	X__val(30);

	return 0;
}

__section("egress")
int emain(struct __sk_buff *skb)
{
	int key = 0, *val, new;

	val = map_lookup_elem(&map_sh, &key);
	if (val) {
		new = *val + 1;
		map_update_elem(&map_sh, &key, &new, 0);
	}

	return BPF_H_DEFAULT;
}

__section("ingress")
int imain(struct __sk_buff *skb)
{
	int key = 0, *val;

	val = map_lookup_elem(&map_sh, &key);
	if (val)
		printt("map val: %d\n", *val);

	return BPF_H_DEFAULT;
}

BPF_LICENSE("GPL");
BPF_KERNEL_VERSION(4, 13, 0);
