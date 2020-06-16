/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <linux/kconfig.h>
#include <linux/version.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#include <linux/tty.h>
#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <linux/netdevice.h>
#include <linux/ns_common.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <net/flow.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <uapi/linux/if.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_arp.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#include <linux/sctp.h>
#pragma clang diagnostic pop

// Custom eBPF includes
#include "bpf/bpf_map.h"
#include "bpf/bpf.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endians.h"

// Shared structures

struct netns_t
{
    u64 netns;
};

struct pidns_t
{
    u64 pidns;
};

struct pid_t
{
    u32 pid;
};

struct cookie_t
{
    u32 cookie;
};

// For the sake of this prototype, this is a limit we fixed because of eBPF limitations
// but in theory the paths can go up to 4096. A production version of this project
// wouldn't use path in maps anyway, so this is an acceptable limitation for this PoC.
#define PATH_MAX_LEN 350

struct exec_path_key_t
{
    u32 cookie;
    char filename[PATH_MAX_LEN];
};

struct device_t
{
    int device_flag;
    int ifindex;
    int group;
    int peer_ifindex;
    u64 netns;
    char name[16];
};

struct arp_h_t
{
    u16 ar_hrd; /* format of hardware address   */
    u16 ar_pro; /* format of protocol address   */
    u8 ar_hln;  /* length of hardware address   */
    u8 ar_pln;  /* length of protocol address   */
    u16 ar_op;  /* ARP opcode (command)     */

    /* Ethernet+IPv4 specific members. */
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address */
    u32 ar_sip;                     /* sender IP address: be32 */
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address */
    u32 ar_tip;                     /* target IP address: be32 */
} __attribute__((packed));

// Data link layer data (L2)
struct ethernet_h_t
{
    u16 h_protocol;                   // Network layer protocol
    unsigned char h_dest[ETH_ALEN];   // Destination hardware (MAC) address
    unsigned char h_source[ETH_ALEN]; // Source hardware (MAC) address
};

// Network layer data (L3)
struct ip_h_t
{
    u8 ip_version; // IP family
    u8 protocol;   // Transport layer protocol
    u16 tot_len;   // Packet total length
    u32 packet_id; // Packet id
    u16 frag_off;  // Fragment offset
    u64 saddr[2];  // Source IP address
    u64 daddr[2];  // Destination address
};

// Transport layer (L4)
struct transport_h_t
{
    u64 flags; // Transport protocol flags (ex: ICMP request, ICMP reply, TCP SYN, TCP ACK, ...)
    u16 sport;
    u16 dport;
};

#define ANY_PROTOCOL 1
#define DNS_PROTOCOL 2
#define HTTP_PROTOCOL 3
#define HTTPS_PROTOCOL 4

// Application layer (L7)
struct app_h_t
{
    u16 protocol; // Protocol
};

#define NO_PROFILE_ALERT_ID 1 << 0
#define NO_DEFAULT_ACTION_ALERT_ID 1 << 1
#define L3_ALERT_ID 1 << 2
#define L4_ALERT_ID 1 << 3
#define L7_ALERT_ID 1 << 4
#define CIDR_ALERT_ID 1 << 5
#define DNS_ALERT_ID 1 << 6
#define ARP_SPOOFING_ALERT_ID 1 << 7

#define EGRESS_DATA_PATH 1
#define INGRESS_DATA_PATH 2
#define EXTERNAL_INTERFACE 1
#define CONTAINER_INTERFACE 2

// ACTION_IGNORE - Ignore any profile infrigement
#define ACTION_IGNORE 0
// ACTION_ALERT - Any infringement to the profile will trigger an alert.
#define ACTION_ALERT 1 << 0
// ACTION_ENFORCE - Any infringement to the profile will cause traffic to be dropped.
#define ACTION_ENFORCE 1 << 1
// ACTION_PROFILE_GENERATION - Any infringement to the profile will will be recorded to improve the security profile
#define ACTION_PROFILE_GENERATION 1 << 2
// ACTION_TRACE_DNS - Traces DNS traffic
#define ACTION_TRACE_DNS 1 << 3

struct net_event_t
{
    /* Probe flag */
    u64 netns;
    u64 timestamp;
    u32 ifindex;
    u32 pid;
    u32 profile_id;
    u32 binary_id;
    u8 action;
    u8 data_path;
    u8 alert_id;
    u8 interface_type;

    /* NAT */
    u32 nat_head_key;

    /* Data link layer data (L2) */
    struct ethernet_h_t eth;

    /* Network layer data (L3) */
    struct ip_h_t ip;

    /* Transport layer data (L4) */
    struct transport_h_t trans;

    /* Application layer data (L7) */
    struct app_h_t app;

    u32 offset;
};

struct session_key_t
{
    u32 ifindex;
    u64 saddr[2];
    u64 daddr[2];
    u16 sport;
    u16 dport;
    u32 h_protocol;
    u32 protocol;
    u32 data_path;
};

#define ONE_MINUTE 60000000UL
#define TEN_MINUTES 600000000UL

struct session_t
{
    u32 bytes_sent;
    u32 bytes_restrans;
    u16 last_frag_offset;
    u32 pid;
    u64 netns;
    u32 head_nat_key;
    u32 next_nat_key;
    u64 timestamp;
};

struct packet_cache_t
{
    struct session_key_t session_key;
    u64 timestamp;
    u8 resolve_nat;
};

struct nat_entry_t
{
    u32 ifindex;
    u64 saddr[2];
    u64 daddr[2];
    u16 sport;
    u16 dport;
    u8 h_dest[ETH_ALEN];
    u8 h_source[ETH_ALEN];
    u32 next_nat_key;
};

struct sched_process_fork_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

struct sched_process_exec_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int data_loc_filename;
    pid_t pid;
    pid_t old_pid;
};

struct sched_process_exit_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char comm[16];
    pid_t pid;
    int prio;
};

#define DNS_MAX_LENGTH 256
#define DNS_A_RECORD 1
#define DNS_AAAA_RECORD 28

struct dns_key_t
{
    char name[DNS_MAX_LENGTH];
    u32 cookie;
    u8 traffic_type;
    u8 layer;
    u16 padding;
};

struct dns_h_t
{
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
};

struct dns_query_spec_t
{
    struct dns_key_t domain;
    u16 qtype;
    u16 qclass;
};

struct dns_query_t
{
    struct net_event_t event;
    struct dns_h_t header;
    struct dns_query_spec_t body;
};

struct dns_response_spec_t
{
    struct dns_key_t domain;
    u64 addr[2];
    u32 ttl;
    u16 type;
    u16 class;
    u16 rdlength;
};

struct dns_response_t
{
    u64 query_timestamp;
    struct net_event_t event;
    struct dns_h_t header;
    struct dns_response_spec_t body;
};

// Network device tracking
static int trace__veth_newlink(struct net_device *dev);
static int trace__register_netdevice(struct net_device *dev);
static int trace__register_netdevice_ret(struct pt_regs *ctx, int ret);
static int trace__dev_change_net_namespace(struct pt_regs *ctx, struct net_device *dev, struct net *net);
static int trace__unregister_netdevice_queue(struct pt_regs *ctx, struct net_device *dev);
static int trace__free_netdev(struct pt_regs *ctx, struct net_device *dev);

// Connection tracking
static int trace__security_sk_classify_flow(struct pt_regs *ctx, struct sock *sk, struct flowi *fl);
static int trace__security_socket_bind(struct pt_regs *ctx, struct socket *sock, struct sockaddr *address, int addrlen);
static int trace__sock_gen_cookie(struct pt_regs *ctx, struct sock *sk);
static int trace__sock_gen_cookie_ret(struct pt_regs *ctx, u64 cookie);

// Network
static int ingress_ext_cls(struct __sk_buff *skb);
static int egress_ext_cls(struct __sk_buff *skb);
static int ingress_cls(struct __sk_buff *skb);
static int egress_cls(struct __sk_buff *skb);
static int cgroup_ingress(struct __sk_buff *skb);
static int cgroup_egress(struct __sk_buff *skb);
static int cgroup_sock(struct bpf_sock *sk);
static int dns_request_tailcall(struct __sk_buff *skb);
static int dns_response_tailcall(struct __sk_buff *skb);
static int cidr_entry_tailcall(struct __sk_buff *skb);
static int parse_packet(struct __sk_buff *skb, struct net_event_t *event);
static int parse_l2(struct ethernet_h_t *h, struct __sk_buff *skb, int *offset);
static int parse_ip(struct ip_h_t *h, struct __sk_buff *skb, int *offset, int h_protocol);
static int parse_arp(struct net_event_t *h, struct __sk_buff *skb, int *offset);
static int parse_l4(struct transport_h_t *h, struct __sk_buff *skb, int *offset, int protocol);
static int parse_l7(struct net_event_t *event, struct __sk_buff *skb, int *offset);
static int parse_dns_query(struct dns_query_t *h, struct __sk_buff *skb, int *offset);
static int parse_dns_response(struct dns_response_t *h, struct __sk_buff *skb, int *offset);
static struct session_t *update_session(struct net_event_t *event);
static int resolve_netns_pid(struct net_event_t *event);
static int assess(struct net_event_t *event, struct session_t *session, struct __sk_buff *skb);
static int assess_l3(struct net_event_t *event, struct session_t *session);
static int assess_l4(struct net_event_t *event, struct session_t *session);
static int assess_l7(struct net_event_t *event, struct session_t *session);
static int assess_cidr(struct net_event_t *event, struct session_t *session);
static int assess_dns_query(struct dns_query_t *query);
static int assess_dns_response(struct dns_response_t *query, struct __sk_buff *skb);
static int insert_cidr_entry(struct dns_response_t *response, u32 cookie);
static int tailcall_dns(struct net_event_t *event, struct session_t *session, struct __sk_buff *skb);
static void assess_network(struct net_event_t *event, struct session_t *session);

// Process tracing
static int trace__do_fork(unsigned long clone_flags,
                          unsigned long stack_start,
                          unsigned long stack_size);
static int trace__sched_sched_process_fork(struct sched_process_fork_args *ctx, pid_t child_pid);
static int trace__sched_sched_process_exec(struct sched_process_exec_args *args);
static int trace__sched_sched_process_exit(struct sched_process_exit_args *args);

// Tools
static u64 netns_from_device(struct net_device *dev);
static void device_from_net_device(struct net_device *netdev, struct device_t *dev);
static void add_nat_entry(struct net_event_t *event, struct session_t *session);
static void new_session_key(struct session_key_t *session_key, struct net_event_t *event);
