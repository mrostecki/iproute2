#ifndef __BPF_API__
#define __BPF_API__

/* Note:
 *
 * This file can be included into eBPF kernel programs. It contains
 * a couple of useful helper functions, map/section ABI (bpf_elf.h),
 * misc macros and some eBPF specific LLVM built-ins.
 */

#include <stdint.h>

#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include <asm/byteorder.h>
//#include <asm/ptrace.h>

#include "bpf_elf.h"

/** Misc macros. */

#ifndef __stringify
# define __stringify(X)		#X
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef offsetof
# define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)
#endif

#ifndef likely
# define likely(X)		__builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
# define unlikely(X)		__builtin_expect(!!(X), 0)
#endif

#ifndef htons
# define htons(X)		__constant_htons((X))
#endif

#ifndef ntohs
# define ntohs(X)		__constant_ntohs((X))
#endif

#ifndef htonl
# define htonl(X)		__constant_htonl((X))
#endif

#ifndef ntohl
# define ntohl(X)		__constant_ntohl((X))
#endif

#ifndef __inline__
# define __inline__		__attribute__((always_inline))
#endif

/** Section helper macros. */

#ifndef __section
# define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __section_xdp_entry
# define __section_xdp_entry						\
	__section(ELF_SECTION_PROG)
#endif

#ifndef __section_cls_entry
# define __section_cls_entry						\
	__section(ELF_SECTION_CLASSIFIER)
#endif

#ifndef __section_act_entry
# define __section_act_entry						\
	__section(ELF_SECTION_ACTION)
#endif

#ifndef __section_lwt_entry
# define __section_lwt_entry						\
	__section(ELF_SECTION_PROG)
#endif

#ifndef __section_license
# define __section_license						\
	__section(ELF_SECTION_LICENSE)
#endif

#ifndef __section_version
# define __section_version						\
	__section(ELF_SECTION_VERSION)
#endif

#ifndef __section_maps
# define __section_maps							\
	__section(ELF_SECTION_MAPS)
#endif

/** Declaration helper macros. */

#ifndef BPF_LICENSE
# define BPF_LICENSE(NAME)						\
	char ____license[] __section_license = NAME
#endif

#define __BPF_KERNEL_VERSION(x, y, z)					\
	(((x) << 16) + ((y) << 8) + (z))

#ifndef BPF_KERNEL_VERSION
# define BPF_KERNEL_VERSION(x, y, z)					\
	int ____version __section_version = __BPF_KERNEL_VERSION((x), (y), (z))
#endif

/** Classifier helper */

#ifndef BPF_H_DEFAULT
# define BPF_H_DEFAULT	-1
#endif

/** BPF helper functions for tc. Individual flags are in linux/bpf.h */

#ifndef __BPF_FUNC
# define __BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) __maybe_unused
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	__BPF_FUNC(NAME, __VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read;

/* Map access/manipulation */
static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static int BPF_FUNC(map_update_elem, void *map, const void *key,
		    const void *value, uint32_t flags);
static int BPF_FUNC(map_delete_elem, void *map, const void *key);

/* Time access */
static uint64_t BPF_FUNC(ktime_get_ns);

/* Debugging */

/* FIXME: __attribute__ ((format(printf, 1, 3))) not possible unless
 * llvm bug https://llvm.org/bugs/show_bug.cgi?id=26243 gets resolved.
 * It would require ____fmt to be made const, which generates a reloc
 * entry (non-map).
 */
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

#ifndef printt
# define printt(fmt, ...)						\
	({								\
		char ____fmt[] = fmt;					\
		trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);	\
	})
#endif

/* Random numbers */
static uint32_t BPF_FUNC(get_prandom_u32);

/* Tail calls */
static void BPF_FUNC(tail_call, struct __sk_buff *skb, void *map,
		     uint32_t index);

/* System helpers */
static uint32_t BPF_FUNC(get_smp_processor_id);
static uint32_t BPF_FUNC(get_numa_node_id);

/* Packet misc meta data */
static uint32_t BPF_FUNC(get_cgroup_classid, struct __sk_buff *skb);
static int BPF_FUNC(skb_under_cgroup, void *map, uint32_t index);

static uint32_t BPF_FUNC(get_route_realm, struct __sk_buff *skb);
static uint32_t BPF_FUNC(get_hash_recalc, struct __sk_buff *skb);
static uint32_t BPF_FUNC(set_hash_invalid, struct __sk_buff *skb);

/* Packet redirection */
static int BPF_FUNC(redirect, int ifindex, uint32_t flags);
static int BPF_FUNC(clone_redirect, struct __sk_buff *skb, int ifindex,
		    uint32_t flags);

/* Packet manipulation */
static int BPF_FUNC(skb_load_bytes, struct __sk_buff *skb, uint32_t off,
		    void *to, uint32_t len);
static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, uint32_t off,
		    const void *from, uint32_t len, uint32_t flags);

static int BPF_FUNC(l3_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static int BPF_FUNC(l4_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static int BPF_FUNC(csum_diff, const void *from, uint32_t from_size,
		    const void *to, uint32_t to_size, uint32_t seed);
static int BPF_FUNC(csum_update, struct __sk_buff *skb, uint32_t wsum);

static int BPF_FUNC(skb_change_type, struct __sk_buff *skb, uint32_t type);
static int BPF_FUNC(skb_change_proto, struct __sk_buff *skb, uint32_t proto,
		    uint32_t flags);
static int BPF_FUNC(skb_change_tail, struct __sk_buff *skb, uint32_t nlen,
		    uint32_t flags);

static int BPF_FUNC(skb_pull_data, struct __sk_buff *skb, uint32_t len);

/* Event notification */
static int __BPF_FUNC(skb_event_output, struct __sk_buff *skb, void *map,
		      uint64_t index, const void *data, uint32_t size) =
		      (void *) BPF_FUNC_perf_event_output;

/* Packet vlan encap/decap */
static int BPF_FUNC(skb_vlan_push, struct __sk_buff *skb, uint16_t proto,
		    uint16_t vlan_tci);
static int BPF_FUNC(skb_vlan_pop, struct __sk_buff *skb);

/* Packet tunnel encap/decap */
static int BPF_FUNC(skb_get_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, uint32_t size, uint32_t flags);
static int BPF_FUNC(skb_set_tunnel_key, struct __sk_buff *skb,
		    const struct bpf_tunnel_key *from, uint32_t size,
		    uint32_t flags);

static int BPF_FUNC(skb_get_tunnel_opt, struct __sk_buff *skb,
		    void *to, uint32_t size);
static int BPF_FUNC(skb_set_tunnel_opt, struct __sk_buff *skb,
		    const void *from, uint32_t size);

/** LLVM built-ins, mem*() routines work for constant size */

#ifndef lock_xadd
# define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

#ifndef memset
# define memset(s, c, n)	__builtin_memset((s), (c), (n))
#endif

#ifndef memcpy
# define memcpy(d, s, n)	__builtin_memcpy((d), (s), (n))
#endif

#ifndef memmove
# define memmove(d, s, n)	__builtin_memmove((d), (s), (n))
#endif

/* FIXME: __builtin_memcmp() is not yet fully useable unless llvm bug
 * https://llvm.org/bugs/show_bug.cgi?id=26218 gets resolved. Also
 * this one would generate a reloc entry (non-map), otherwise.
 */
#if 0
#ifndef memcmp
# define memcmp(a, b, n)	__builtin_memcmp((a), (b), (n))
#endif
#endif

unsigned long long load_byte(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.byte");

unsigned long long load_half(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.half");

unsigned long long load_word(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.word");

struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_ax;
/* Return frame for iretq */
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
/* top of stack page */
};


#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({				\
		bpf_probe_read(&(ip), sizeof(ip), (void *)PT_REGS_RET(ctx)); })

#define BPF_KRETPROBE_READ_RET_IP(ip, ctx)	({				\
		bpf_probe_read(&(ip), sizeof(ip),				\
				(void *)(PT_REGS_FP(ctx) + sizeof(ip))); })

#define bpf_walk(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#endif /* __BPF_API__ */
