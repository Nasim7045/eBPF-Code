#include "vmlinux.h"

/* Manual type definitions */
typedef unsigned int __u32;
typedef unsigned long long __u64;

/* Network constants */
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TARGET_PORT 4040

/* BPF includes */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;
    
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;
    
    /* Only allow traffic to TARGET_PORT */
    if (bpf_ntohs(tcp->dest) != TARGET_PORT)
        return XDP_DROP;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
