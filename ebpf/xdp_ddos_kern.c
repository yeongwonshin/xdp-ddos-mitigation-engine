// SPDX-License-Identifier: MIT
// Defensive XDP DDoS mitigation fast path.
// This program classifies IPv4 TCP SYN/UDP/ICMP packets, enforces per-source
// sliding-window rate limits, honors allow/block lists, and applies reputation
// based drops. It is intentionally small so that complex policy decisions stay
// in user space.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "MIT";

#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define NSEC_PER_SEC 1000000000ULL

#define STAT_PASS 0
#define STAT_DROP_BLOCKLIST 1
#define STAT_DROP_REPUTATION 2
#define STAT_DROP_SYN_RATE 3
#define STAT_DROP_UDP_RATE 4
#define STAT_DROP_ICMP_RATE 5
#define STAT_DROP_MALFORMED 6
#define STAT_TOTAL 7

struct policy_config {
    __u32 syn_pps_limit;
    __u32 udp_pps_limit;
    __u32 icmp_pps_limit;
    __u32 reputation_drop_score;
    __u32 allowlist_enabled;
    __u32 blocklist_enabled;
    __u32 reputation_enabled;
    __u32 audit_only;
};

struct rate_key {
    __u32 src_ip;       // network-byte-order IPv4 address from packet
    __u8 proto;
    __u8 pad1;
    __u16 dst_port;     // network-byte-order for TCP/UDP; 0 for ICMP
};

struct rate_value {
    __u64 window_start_ns;
    __u32 count;
    __u32 last_action;
};

struct reputation_value {
    __u32 score;        // 0-100, maintained by control plane
    __u64 updated_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct rate_key);
    __type(value, struct rate_value);
} rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} allowlist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);
    __type(value, struct reputation_value);
} reputation_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_TOTAL);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void incr_stat(__u32 idx)
{
    __u64 *counter = bpf_map_lookup_elem(&stats_map, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline int drop_or_pass(const struct policy_config *cfg, __u32 stat_idx)
{
    incr_stat(stat_idx);
    if (cfg && cfg->audit_only)
        return XDP_PASS;
    return XDP_DROP;
}

static __always_inline int parse_ipv4(void *data, void *data_end,
                                      struct iphdr **iph_out, __u64 *offset)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    *offset = sizeof(*eth);

    // Minimal VLAN support for one 802.1Q or 802.1AD tag.
    if (h_proto == 0x8100 || h_proto == 0x88a8) {
        struct vlan_hdr_min {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        };
        struct vlan_hdr_min *vh = data + *offset;
        if ((void *)(vh + 1) > data_end)
            return -1;
        h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
        *offset += sizeof(*vh);
    }

    if (h_proto != ETH_P_IP)
        return 1;

    struct iphdr *iph = data + *offset;
    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->ihl < 5)
        return -1;

    __u64 ihl_len = iph->ihl * 4;
    if ((void *)iph + ihl_len > data_end)
        return -1;

    *iph_out = iph;
    *offset += ihl_len;
    return 0;
}

static __always_inline int rate_limited(struct rate_key *key, __u32 limit)
{
    if (limit == 0)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    struct rate_value *cur = bpf_map_lookup_elem(&rate_map, key);

    if (!cur) {
        struct rate_value init = {
            .window_start_ns = now,
            .count = 1,
            .last_action = XDP_PASS,
        };
        bpf_map_update_elem(&rate_map, key, &init, BPF_ANY);
        return 0;
    }

    if (now - cur->window_start_ns >= NSEC_PER_SEC) {
        cur->window_start_ns = now;
        cur->count = 1;
        cur->last_action = XDP_PASS;
        return 0;
    }

    cur->count += 1;
    if (cur->count > limit) {
        cur->last_action = XDP_DROP;
        return 1;
    }

    return 0;
}

SEC("xdp")
int xdp_ddos_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 cfg_key = 0;
    struct policy_config default_cfg = {
        .syn_pps_limit = 2000,
        .udp_pps_limit = 5000,
        .icmp_pps_limit = 1000,
        .reputation_drop_score = 80,
        .allowlist_enabled = 1,
        .blocklist_enabled = 1,
        .reputation_enabled = 1,
        .audit_only = 1,
    };
    struct policy_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg)
        cfg = &default_cfg;

    struct iphdr *iph = 0;
    __u64 offset = 0;
    int p = parse_ipv4(data, data_end, &iph, &offset);
    if (p == 1) {
        incr_stat(STAT_PASS);
        return XDP_PASS;
    }
    if (p < 0)
        return drop_or_pass(cfg, STAT_DROP_MALFORMED);

    __u32 src_ip = iph->saddr;

    if (cfg->allowlist_enabled) {
        __u8 *allowed = bpf_map_lookup_elem(&allowlist_map, &src_ip);
        if (allowed && *allowed) {
            incr_stat(STAT_PASS);
            return XDP_PASS;
        }
    }

    if (cfg->blocklist_enabled) {
        __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
        if (blocked && *blocked)
            return drop_or_pass(cfg, STAT_DROP_BLOCKLIST);
    }

    if (cfg->reputation_enabled) {
        struct reputation_value *rep = bpf_map_lookup_elem(&reputation_map, &src_ip);
        if (rep && rep->score >= cfg->reputation_drop_score)
            return drop_or_pass(cfg, STAT_DROP_REPUTATION);
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + offset;
        if ((void *)(tcp + 1) > data_end)
            return drop_or_pass(cfg, STAT_DROP_MALFORMED);

        if (tcp->syn && !tcp->ack) {
            struct rate_key key = {
                .src_ip = src_ip,
                .proto = IPPROTO_TCP,
                .dst_port = tcp->dest,
            };
            if (rate_limited(&key, cfg->syn_pps_limit))
                return drop_or_pass(cfg, STAT_DROP_SYN_RATE);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + offset;
        if ((void *)(udp + 1) > data_end)
            return drop_or_pass(cfg, STAT_DROP_MALFORMED);

        struct rate_key key = {
            .src_ip = src_ip,
            .proto = IPPROTO_UDP,
            .dst_port = udp->dest,
        };
        if (rate_limited(&key, cfg->udp_pps_limit))
            return drop_or_pass(cfg, STAT_DROP_UDP_RATE);
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = data + offset;
        if ((void *)(icmp + 1) > data_end)
            return drop_or_pass(cfg, STAT_DROP_MALFORMED);

        struct rate_key key = {
            .src_ip = src_ip,
            .proto = IPPROTO_ICMP,
            .dst_port = 0,
        };
        if (rate_limited(&key, cfg->icmp_pps_limit))
            return drop_or_pass(cfg, STAT_DROP_ICMP_RATE);
    }

    incr_stat(STAT_PASS);
    return XDP_PASS;
}
