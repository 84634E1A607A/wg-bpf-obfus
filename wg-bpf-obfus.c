/* .c
 *
 * Build:
 *   clang -O2 -Wall -target bpf -c wg-bpf-obfus.c -o wg-bpf-obfus.o
 *
 * Attach:
 *   tc qdisc add dev eth0 clsact               # once per iface
 *   tc filter add dev eth0  ingress bpf da obj wg-bpf-obfus.o sec classifier
 *   tc filter add dev eth0  egress  bpf da obj wg-bpf-obfus.o sec classifier
 * 
 * Detach:
 *   tc filter del dev eth0 ingress
 *   tc filter del dev eth0 egress
 * 
 * Description:
 *   This BPF program mutates the first 4 bytes of WireGuard packets so it is
 *   not easily recognizable by simple pattern matching.
 * 
 * Deploy:
 *   Use systemd service to load the BPF program on boot. See wg-bpf-obfus.service
 *
 * License: MIT
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>   /* TC_ACT_OK */
#include <linux/in.h>        /* IPPROTO_UDP */
#include <stdbool.h>
#include <bpf/bpf_endian.h>   /* bpf_ntohs / bpf_htons */

#define PORT 51820           /* the hard-coded UDP port */
#define SECRET 0x00          /* XOR secret for obfuscation, quite simple though */

static __always_inline bool is_ingress(const struct __sk_buff *skb)
{
    /* On the tc ingress hook, ingress_ifindex is the real interface index;
     * on egress it is 0.  That’s reliable from kernel ≥ 4.17. */
    return skb->ingress_ifindex != 0;
}

SEC("classifier")
int wg_obfus(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    bool ingress = is_ingress(skb);

    /* ── Determine link-layer type ────────────────────────────── */
    __u64 nh_off  = 0;
    __u16 h_proto = bpf_ntohs(skb->protocol);

    if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6) {
        /* Not an L3 device – assume Ethernet header in front */
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return TC_ACT_OK;
        h_proto = bpf_ntohs(eth->h_proto);
        nh_off  = sizeof(*eth);
    }

    /* ── IPv4 / IPv6 header ───────────────────────────────────── */
    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = data + nh_off;
        if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_UDP)
            return TC_ACT_OK;
        nh_off += iph->ihl * 4;
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data + nh_off;
        if ((void *)(ip6h + 1) > data_end || ip6h->nexthdr != IPPROTO_UDP)
            return TC_ACT_OK;
        nh_off += sizeof(*ip6h);
    } else {
        return TC_ACT_OK;
    }

    /* ── UDP header ───────────────────────────────────────────── */
    struct udphdr *udph = data + nh_off;
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    __u16 src = bpf_ntohs(udph->source);
    __u16 dst = bpf_ntohs(udph->dest);

    /* ── Direction-aware port check ───────────────────────────── */
    if (ingress) {
        if (dst != PORT)
            return TC_ACT_OK;                       /* not target inbound */
    } else {                                        /* egress */
        if (src != PORT)
            return TC_ACT_OK;                       /* not target outbound */
    }

    /* ── Ensure we have at least 4-byte payload ───────────────── */
    __u16 udp_len = bpf_ntohs(udph->len);
    if (udp_len < 8 + 4)                            /* header + 4 bytes */
        return TC_ACT_OK;

    __u64 poff = nh_off + sizeof(*udph);
    if (data + poff + 4 > data_end)
        return TC_ACT_OK;

    __u8 *pl = data + poff;

    /* ── Transform first 4 bytes ──────────────────────────────── */
    __u32 new; /* network byte order */
    
    /* We add simple xor ops here to obfuscate and hide the distinguishing feature of WireGuard */
    if (ingress) {
        __u32 random = ((pl[1] ^ pl[2]) + pl[3]) & 0xff;  /* Calculate the random part */
        new = bpf_htonl((pl[0] ^ random ^ SECRET) << 24); /* Restore the actual bytes */
    }
    else {
        __u32 rnd = bpf_get_prandom_u32() & 0x00ffffff;           /* Randomize the other 3 bytes */
        __u32 random = (((rnd >> 16) ^ (rnd >> 8)) + rnd) & 0xff; /* Calculate the random part */
        new = bpf_htonl((pl[0] ^ random ^ SECRET) << 24 | rnd);   /* XOR the actual byte */
    }

    __u32 old = *(__u32 *)pl; /* original first 4 bytes, network byte order */
    *(__u32 *)pl = new;

    /* ── Incremental checksum fix-up for ingress ──────────────── */
    if (ingress && udph->check) { /* IPv4 checksum can be 0 ⇒ “no-checksum” */
        /* byte offset of the UDP checksum inside the packet */
        __u32 csum_off = nh_off + offsetof(struct udphdr, check);

        /*  ▸ size (lower 4 bits) = 4 because we changed 4 bytes
         *  ▸ BPF_F_PSEUDO_HDR    : helper must include the UDP pseudo header
         *  ▸ BPF_F_MARK_MANGLED_0: preserve/produce CSUM_MANGLED_0 when result is 0
         */
        bpf_l4_csum_replace(skb, csum_off,
                            old,             /* from */
                            new,             /* to   */
                            BPF_F_PSEUDO_HDR |
                            BPF_F_MARK_MANGLED_0 |
                            sizeof(__u32));  /* = 4, fits in the low nibble */
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "MIT";
