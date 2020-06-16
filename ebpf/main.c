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
#include "main.h"

/**
 * eBPF hooks section
 * ------------------
 *
 * This section defines all the hook points in the kernel that the
 * network-security-probe is using.
 */

SEC("kprobe/veth_newlink")
int kprobe__veth_newlink(struct pt_regs *ctx)
{
    // struct net *src_net = (struct net *)PT_REGS_PARM1(ctx);
    struct net_device *dev = (struct net_device *)PT_REGS_PARM2(ctx);
    return trace__veth_newlink(dev);
};

SEC("kprobe/register_netdevice")
int kprobe__register_netdevice(struct pt_regs *ctx)
{
    struct net_device *dev = (struct net_device *)PT_REGS_PARM1(ctx);
    return trace__register_netdevice(dev);
};

SEC("kretprobe/register_netdevice")
int kretprobe__register_netdevice(struct pt_regs *ctx)
{
    int ret = PT_REGS_RET(ctx);
    return trace__register_netdevice_ret(ctx, ret);
};

SEC("kprobe/dev_change_net_namespace")
int kprobe__dev_change_net_namespace(struct pt_regs *ctx)
{
    struct net_device *dev = (struct net_device *)PT_REGS_PARM1(ctx);
    struct net *net = (struct net *)PT_REGS_PARM2(ctx);
    // const char *pat = (const char *)PT_REGS_PARM3(ctx);
    return trace__dev_change_net_namespace(ctx, dev, net);
};

SEC("kprobe/unregister_netdevice_queue")
int kprobe__unregister_netdevice_queue(struct pt_regs *ctx)
{
    struct net_device *dev = (struct net_device *)PT_REGS_PARM1(ctx);
    return trace__unregister_netdevice_queue(ctx, dev);
};

SEC("kprobe/free_netdev")
int kprobe__free_netdev(struct pt_regs *ctx)
{
    struct net_device *dev = (struct net_device *)PT_REGS_PARM1(ctx);
    return trace__free_netdev(ctx, dev);
};

SEC("kprobe/security_sk_classify_flow")
int kprobe__security_sk_classify_flow(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct flowi *fl = (struct flowi *)PT_REGS_PARM2(ctx);
    return trace__security_sk_classify_flow(ctx, sk, fl);
};

SEC("kprobe/security_socket_bind")
int kprobe__security_socket_bind(struct pt_regs *ctx)
{
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    int addrlen = PT_REGS_PARM3(ctx);
    return trace__security_socket_bind(ctx, sock, address, addrlen);
};

SEC("kprobe/sock_gen_cookie")
int kprobe__sock_gen_cookie(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    return trace__sock_gen_cookie(ctx, sk);
};

SEC("kprobe/_do_fork")
int kprobe__do_fork(struct pt_regs *ctx)
{
    unsigned long clone_flags = PT_REGS_PARM1(ctx);
    unsigned long stack_start = PT_REGS_PARM2(ctx);
    unsigned long stack_size = PT_REGS_PARM3(ctx);
    return trace__do_fork(clone_flags, stack_start, stack_size);
}

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct sched_process_fork_args *ctx)
{
    pid_t child_pid = ctx->child_pid;
    return trace__sched_sched_process_fork(ctx, child_pid);
}

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct sched_process_exec_args *ctx)
{
    return trace__sched_sched_process_exec(ctx);
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct sched_process_exit_args *ctx)
{
    return trace__sched_sched_process_exit(ctx);
}

SEC("kretprobe/sock_gen_cookie")
int kprobe__sock_gen_cookie_ret(struct pt_regs *ctx)
{
    u64 cookie = PT_REGS_RET(ctx);
    return trace__sock_gen_cookie_ret(ctx, cookie);
};

SEC("classifier/ingress_ext_cls")
int ingress_ext_cls_func(struct __sk_buff *skb)
{
    return ingress_ext_cls(skb);
};

SEC("classifier/egress_ext_cls")
int egress_ext_cls_func(struct __sk_buff *skb)
{
    return egress_ext_cls(skb);
};

SEC("classifier/ingress_cls")
int ingress_cls_func(struct __sk_buff *skb)
{
    return ingress_cls(skb);
};

SEC("classifier/egress_cls")
int egress_cls_func(struct __sk_buff *skb)
{
    return egress_cls(skb);
};

SEC("classifier/dns_request_parser")
int dns_request_parser(struct __sk_buff *skb)
{
    return dns_request_tailcall(skb);
};

SEC("classifier/dns_response_parser")
int dns_response_parser(struct __sk_buff *skb)
{
    return dns_response_tailcall(skb);
};

SEC("classifier/cidr_entry")
int cidr_entry(struct __sk_buff *skb)
{
    return cidr_entry_tailcall(skb);
};

SEC("cgroup/sock/sock")
int cgroup_sock_func(struct bpf_sock *sk)
{
    return cgroup_sock(sk);
};

SEC("cgroup/skb/ingress")
int cgroup_ingress_func(struct __sk_buff *skb)
{
    return cgroup_ingress(skb);
};

SEC("cgroup/skb/egress")
int cgroup_egress_func(struct __sk_buff *skb)
{
    return cgroup_egress(skb);
};

SEC("sockops/op")
int bpf_clamp(struct bpf_sock_ops *skops)
{
    // bpf_printk("remote:%d local:%d\n", bpf_ntohl(skops->remote_port), skops->local_port);
    return 1;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

/**
 * Generic structures
 */

#define TTY_NAME_LEN 64

typedef struct metadata_t
{
    u64 pidns;
    u64 netns;
    u64 timestamp;
    char tty_name[TTY_NAME_LEN];
    u32 pid;
    u32 tid;
} metadata_t;

__attribute__((always_inline)) static u64 fill_metadata(struct metadata_t *data)
{
    // Timestamp
    data->timestamp = bpf_ktime_get_ns();
    // Pidns
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy;
    bpf_probe_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    struct pid_namespace *pid_ns;
    bpf_probe_read(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
    bpf_probe_read(&data->pidns, sizeof(data->pidns), &pid_ns->ns.inum);
    // netns
    struct net *net_ns;
    bpf_probe_read(&net_ns, sizeof(net_ns), &nsproxy->net_ns);
    bpf_probe_read(&data->netns, sizeof(data->netns), &net_ns->ns.inum);
    // TTY
    struct signal_struct *signal;
    bpf_probe_read(&signal, sizeof(signal), &task->signal);
    struct tty_struct *tty;
    bpf_probe_read(&tty, sizeof(tty), &signal->tty);
    bpf_probe_read_str(data->tty_name, TTY_NAME_LEN, tty->name);
    // Pid & Tid
    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;
    data->tid = id;
    return id;
};

/**
 * Profile maps
 */

/**
 * cidr_ranges is the map used to save the IP ranges of the profile
 * WARNING: it has to be the first map defined in the `maps/cidr_rules`
 * section since it is referred to as map #0 in further maps definition.
 */
struct bpf_map_def SEC("maps/cidr_rules") cidr_ranges = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = 24,
    .value_size = sizeof(u64),
    .max_entries = 1024,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct cidr_rule_t
{
    u32 cookie;
    u16 protocol;
    u8 traffic_type;
};

struct bpf_map_def SEC("maps/cidr_rules") cidr_rules = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(struct cidr_rule_t),
    .max_entries = 1024,
    .inner_map_idx = 0, /* map_fd[0] is cidr_ranges */
};

struct protocol_key_t
{
    u32 cookie;
    u16 protocol;
    u8 traffic_type;
    u8 layer;
};

struct bpf_map_def SEC("maps/protocol_rules") protocol_rules = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct protocol_key_t),
    .value_size = sizeof(int),
    .max_entries = 515,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct cookie_key_t
{
    u32 cookie;
};

struct bpf_map_def SEC("maps/network_attacks_rules") network_attacks_rules = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct cookie_key_t),
    .value_size = sizeof(int),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/action_rules") action_rules = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct cookie_key_t),
    .value_size = sizeof(int),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct protocol_port_key_t
{
    u32 cookie;
    u16 protocol;
    u16 port;
    u8 traffic_type;
};

struct bpf_map_def SEC("maps/protocol_port_rules") protocol_port_rules = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct protocol_port_key_t),
    .value_size = sizeof(int),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/dns_rules") dns_rules = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct dns_key_t),
    .value_size = sizeof(int),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

#define HTTP_URI_MAX 128
#define HTTP_METHOD_MAX 10

struct http_key_t
{
    u8 traffic_type;
    u32 cookie;
    char method[HTTP_METHOD_MAX];
    char uri[HTTP_URI_MAX];
};

struct bpf_map_def SEC("maps/http_rules") http_rules = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct http_key_t),
    .value_size = sizeof(int),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/netns_profile_id") netns_profile_id = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct netns_t),
    .value_size = sizeof(struct cookie_t),
    .max_entries = 513,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/pidns_profile_id") pidns_profile_id = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct pidns_t),
    .value_size = sizeof(struct cookie_t),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/pid_binary_id") pid_binary_id = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct pid_t),
    .value_size = sizeof(struct cookie_t),
    .max_entries = 511,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/path_binary_id") path_binary_id = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct exec_path_key_t),
    .value_size = sizeof(struct cookie_t),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Network device tracking
 * -----------------------
 *
 * The goal of this section is to track the lifecycle of network devices
 * in the kernel.
 *
 * Veth device creation state machine
 */

#define STATE_NULL 0
#define STATE_NEWLINK 1
#define STATE_REGISTER_PEER 2

struct veth_state_t
{
    int state;
    int peer_ifindex;
};

struct bpf_map_def SEC("maps/veth_state_machine") veth_state_machine = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct veth_state_t),
    .max_entries = 128,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Network device hash maps
 */

#define PEER_DEVICE 0
#define DEVICE 1

struct bpf_map_def SEC("maps/devices") devices = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct device_t),
    .max_entries = 512,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Network device registration cache
 */

struct net_device_cache_value_t
{
    struct net_device *net_device;
};

struct bpf_map_def SEC("maps/net_device_cache") net_device_cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct net_device_cache_value_t),
    .max_entries = 128,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Network device registration perf event
 */

#define DEVICE_REGISTRATION 0
#define DEVICE_UNREGISTRATION 1
#define DEVICE_FREE 2

struct device_event_t
{
    u64 event_flag;
    struct metadata_t meta;
    struct device_t device;
    struct device_t peer;
};

struct bpf_map_def SEC("maps/device_events") device_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct device_netns_update_t
{
    struct metadata_t meta;
    struct device_t device;
    u64 new_netns;
};

struct bpf_map_def SEC("maps/device_netns_update") device_netns_update = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Ifindex netns matching map
 */

struct bpf_map_def SEC("maps/ifindex_netns") ifindex_netns = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct netns_t),
    .max_entries = 514,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * trace__veth_newlink - Traces the creation request of a new veth pair
 * for the provided device.
 * @dev: device, some members of this structure might not yet be set
 *
 * Regardless of the previous state of the "veth device" state machine
 * associated to the current PID, this function will set it to:
 * STATE_NEWLINK.
 */
__attribute__((always_inline)) static int trace__veth_newlink(struct net_device *dev)
{
    // Set the veth_state_machine to STATE_NEWLINK for the current pid
    u64 id = bpf_get_current_pid_tgid();
    struct veth_state_t state = {
        .state = STATE_NEWLINK,
        .peer_ifindex = 0, // will be filled in the next state
    };
    bpf_map_update_elem(&veth_state_machine, &id, &state, BPF_ANY);
    return 0;
};

/**
 * trace__register_netdevice - Traces the registration of a new network
 * device in the kernel.
 * @dev: the device structure after registration in the kernel
 */
__attribute__((always_inline)) static int trace__register_netdevice(struct net_device *dev)
{
    // Cache network device pointer for the return kprobe
    u64 key = bpf_get_current_pid_tgid();
    struct net_device_cache_value_t val = {
        .net_device = dev,
    };
    bpf_map_update_elem(&net_device_cache, &key, &val, BPF_ANY);
    return 0;
};

/**
 * trace__register_netdevice_ret - Traces the return of a new device registration
 * in the kernel.
 * @ret: the return value
 */
__attribute__((always_inline)) static int trace__register_netdevice_ret(struct pt_regs *ctx, int ret)
{
    u64 key = bpf_get_current_pid_tgid();
    // Get the network device pointer
    struct net_device_cache_value_t *cache_entry = bpf_map_lookup_elem(&net_device_cache, &key);
    if (cache_entry == NULL)
    {
        return 0;
    }
    struct device_t dev = {};
    device_from_net_device(cache_entry->net_device, &dev);
    // Delete cache entry
    bpf_map_delete_elem(&net_device_cache, &key);
    // Get state from per CPU hashmap
    struct veth_state_t *state = bpf_map_lookup_elem(&veth_state_machine, &key);
    if (state == NULL)
    {
        // Handle this new device as a single device
        struct device_event_t evt = {
            .event_flag = DEVICE_REGISTRATION,
            .device = dev,
        };
        fill_metadata(&evt.meta);
        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &device_events, cpu, &evt, sizeof(evt));
        // Update ifindex_netns entry
        struct netns_t nns = {
            .netns = dev.netns,
        };
        bpf_map_update_elem(&ifindex_netns, &dev.ifindex, &nns, BPF_ANY);
        return 0;
    }

    switch (state->state)
    {
    case STATE_NEWLINK:
        // Save the Peer device
        dev.device_flag = PEER_DEVICE;
        bpf_map_update_elem(&devices, &dev.ifindex, &dev, BPF_ANY);
        // Update the state machine
        state->state = STATE_REGISTER_PEER;
        state->peer_ifindex = dev.ifindex;
        break;
    case STATE_REGISTER_PEER:
        // Save the device
        dev.device_flag = DEVICE;
        dev.peer_ifindex = state->peer_ifindex;
        bpf_map_update_elem(&devices, &dev.ifindex, &dev, BPF_ANY);
        // Update peer device
        struct device_t *peer = bpf_map_lookup_elem(&devices, &dev.peer_ifindex);
        if (peer != NULL)
        {
            peer->peer_ifindex = dev.ifindex;
            return 0;
        }
        // Delete state machine entry
        bpf_map_delete_elem(&veth_state_machine, &key);
        break;
    default:
        break;
    }
    return 0;
};

/**
 * trace__dev_change_net_namespace - Traces devices that swith network
 * namespace.
 * @dev: device
 * @net: new network namespace
 */
__attribute__((always_inline)) static int trace__dev_change_net_namespace(struct pt_regs *ctx, struct net_device *netdev, struct net *net)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct device_netns_update_t evt = {};
    fill_metadata(&evt.meta);
    device_from_net_device(netdev, &evt.device);
    struct ns_common ns_co;
    bpf_probe_read(&ns_co, sizeof(ns_co), &net->ns);
    evt.new_netns = ns_co.inum;
    // Try to select the device and its veth pair
    struct device_t *dev = bpf_map_lookup_elem(&devices, &evt.device.ifindex);
    if (dev != NULL)
    {
        // A veth pair was created and one part of the pair is moving to its final netns.
        int peer_ifindex = dev->peer_ifindex;
        struct device_t *peer = bpf_map_lookup_elem(&devices, &peer_ifindex);
        if (peer != NULL)
        {
            struct device_event_t device_evt = {
                .event_flag = DEVICE_REGISTRATION,
                .device = *peer,
                .peer = *dev,
            };
            fill_metadata(&device_evt.meta);
            // Notify Veth pair creation
            bpf_perf_event_output(ctx, &device_events, cpu, &device_evt, sizeof(device_evt));
            // Delete device
            bpf_map_delete_elem(&devices, &peer_ifindex);
            // Update ifindex_netns entry
            struct netns_t nns = {
                .netns = evt.new_netns,
            };
            bpf_map_update_elem(&ifindex_netns, &peer_ifindex, &nns, BPF_ANY);
        }
        // Delete peer device
        bpf_map_delete_elem(&devices, &evt.device.ifindex);
    }
    // Notify device netns update
    bpf_perf_event_output(ctx, &device_netns_update, cpu, &evt, sizeof(evt));
    return 0;
};

/**
 * trace__unregister_netdevice_queue - Traces devices that are about to
 * get unregisterd from the kernel.
 * @dev: the device structure before it is unregistered.
 */
__attribute__((always_inline)) static int trace__unregister_netdevice_queue(struct pt_regs *ctx, struct net_device *netdev)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct device_event_t evt = {
        .event_flag = DEVICE_UNREGISTRATION,
    };
    fill_metadata(&evt.meta);
    device_from_net_device(netdev, &evt.device);
    // Notify device unregistration
    bpf_perf_event_output(ctx, &device_events, cpu, &evt, sizeof(evt));
    // Delete ifindex_netns entry
    bpf_map_delete_elem(&ifindex_netns, &evt.device.ifindex);
    return 0;
};

/**
 * trace__free_netdev - Traces devices that the kernel is about to freed.
 * @dev: the device structure befor it is freed.
 */
__attribute__((always_inline)) static int trace__free_netdev(struct pt_regs *ctx, struct net_device *netdev)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct device_event_t evt = {
        .event_flag = DEVICE_FREE,
    };
    fill_metadata(&evt.meta);
    device_from_net_device(netdev, &evt.device);
    // Notify device unregistration
    bpf_perf_event_output(ctx, &device_events, cpu, &evt, sizeof(evt));
    return 0;
};

/**
 * Connection tracking
 * -------------------
 *
 * The goal of this section is to track processes that are trying to
 * connect to a remote server or opening a service to the world.
 */

/**
 * Map cookie
 */

struct map_cookie_t
{
    u32 cookie;
};

struct bpf_map_def SEC("maps/map_cookie") map_cookie = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct map_cookie_t),
    .max_entries = 1,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Service PID matching with registered flow
 */

struct flow_pid_key_t
{
    u64 addr_0;
    u64 addr_1;
    u64 netns;
    u16 port;
};

struct flow_pid_value_t
{
    u32 pid;
};

struct bpf_map_def SEC("maps/flow_pid") flow_pid = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct flow_pid_key_t),
    .value_size = sizeof(struct flow_pid_value_t),
    .max_entries = 1024,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Flow perf event
 */

struct flow_t
{
    struct metadata_t meta;
    u64 addr[2];
    u16 port;
    u16 family;
};

struct bpf_map_def SEC("maps/flows") flows = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * trace__security_sk_classify_flow - Traces processes that are trying
 * to reach out to a remote service.
 * @fl: routing flow of the outgoing traffic
 */
__attribute__((always_inline)) static int trace__security_sk_classify_flow(struct pt_regs *ctx, struct sock *sk, struct flowi *fl)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct flow_t evt = {};
    fill_metadata(&evt.meta);
    bpf_probe_read(&evt.family, sizeof(evt.family), &sk->sk_family);
    union flowi_uli uli;
    if (evt.family == AF_INET6)
    {
        struct flowi6 ip6;
        bpf_probe_read(&ip6, sizeof(ip6), &fl->u.ip6);
        bpf_probe_read(&uli, sizeof(uli), &ip6.uli);
        bpf_probe_read(&evt.port, sizeof(evt.port), &uli.ports.sport);
        // struct in6_addr in6;
        // bpf_probe_read(&in6, sizeof(in6), &ip6.saddr);
        // bpf_probe_read(&evt.addr, sizeof(u64) * 2, &in6.in6_u);
        bpf_probe_read(&evt.addr, sizeof(u64) * 2, &ip6.saddr);
    }
    else if (evt.family == AF_INET)
    {
        struct flowi4 ip4;
        bpf_probe_read(&ip4, sizeof(ip4), &fl->u.ip4);
        bpf_probe_read(&uli, sizeof(uli), &ip4.uli);
        bpf_probe_read(&evt.port, sizeof(evt.port), &uli.ports.sport);
        bpf_probe_read(&evt.addr, sizeof(sk->__sk_common.skc_rcv_saddr), &sk->__sk_common.skc_rcv_saddr);
        u8 type = 0;
        u8 code = 0;
        bpf_probe_read(&type, sizeof(type), &uli.icmpt.type);
        bpf_probe_read(&code, sizeof(code), &uli.icmpt.code);
        // bpf_printk("type:%d code:%d\n", type, code);
    }
    else
    {
        return 0;
    }
    evt.port = be16_to_cpu(evt.port);
    bpf_perf_event_output(ctx, &flows, cpu, &evt, sizeof(evt));
    // Register service PID
    if (evt.port != 0)
    {
        struct flow_pid_key_t key = {
            .netns = evt.meta.netns,
            .port = evt.port,
        };
        key.addr_0 = evt.addr[0];
        key.addr_1 = evt.addr[1];
        struct flow_pid_value_t sdata = {
            .pid = evt.meta.pid,
        };
        bpf_map_update_elem(&flow_pid, &key, &sdata, BPF_ANY);
        // bpf_printk("# registered (flow) pid:%d\n", sdata.pid);
        // bpf_printk("# p:%d a:%d a:%d\n", evt.port, evt.addr[0], evt.addr[1]);
    }
    // TODO: If evt.port == 0 it is because the process is communicating with a protocol that doesn't require
    // a port (for example ICMP or ARP). In this case, the flow contains data about the ICMP request. It can be used to map
    // it back to the right process.
    return 0;
};

/**
 * trace__security_socket_bind - Traces processes that are binding a
 * socket to a local address.
 * @sock: socket
 * @address: address
 * @addrlen: address length
 */
__attribute__((always_inline)) static int trace__security_socket_bind(struct pt_regs *ctx, struct socket *sock, struct sockaddr *address, int addrlen)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct flow_t evt = {};
    fill_metadata(&evt.meta);
    // Register service PID
    bpf_probe_read(&evt.family, sizeof(evt.family), &address->sa_family);
    if (evt.family == AF_INET)
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        bpf_probe_read(&evt.port, sizeof(addr_in->sin_port), &addr_in->sin_port);
        bpf_probe_read(&evt.addr, sizeof(addr_in->sin_addr.s_addr), &addr_in->sin_addr.s_addr);
    }
    else if (evt.family == AF_INET6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
        bpf_probe_read(&evt.port, sizeof(addr_in6->sin6_port), &addr_in6->sin6_port);
        bpf_probe_read(&evt.addr, sizeof(u64) * 2, (char *)addr_in6 + offsetof(struct sockaddr_in6, sin6_addr));
    }
    else
    {
        return 0;
    }
    evt.port = be16_to_cpu(evt.port);
    bpf_perf_event_output(ctx, &flows, cpu, &evt, sizeof(evt));
    // Register service PID
    if (evt.port != 0)
    {
        struct flow_pid_key_t key = {
            .port = evt.port,
        };
        key.addr_0 = evt.addr[0];
        key.addr_1 = evt.addr[1];
        bpf_probe_read(&key.netns, sizeof(key.netns), &evt.meta.netns);
        struct flow_pid_value_t sdata = {
            .pid = evt.meta.pid,
        };
        bpf_map_update_elem(&flow_pid, &key, &sdata, BPF_ANY);
        // bpf_printk("# registered (bind) pid:%d\n", sdata.pid);
        // bpf_printk("# p:%d a:%d a:%d\n", evt.port, evt.addr[0], evt.addr[1]);
    }
    return 0;
};

/**
 * trace__sock_gen_cookie - Traces sock_gen_cookie
 * @sk: sock structure
 */
__attribute__((always_inline)) static int trace__sock_gen_cookie(struct pt_regs *ctx, struct sock *sk)
{
    // Check if the cookie should be resolved in a pid
    // int key = 0;
    // struct map_cookie c = {};
    // bpf_probe_read(&c.sk, sizeof(struct sock *), &sk);
    // bpf_map_update_elem(&trace_cookie, &key, &c, BPF_ANY);
    // if (trace == NULL)
    // {
    //     return 0;
    // }
    // if (trace->trace != 1)
    // {
    //     return 0;
    // }
    // trace->sk = sk;
    return 0;
};

/**
 * trace__sock_gen_cookie_ret - Traces the return value of sock_gen_cookie
 * @cookie: cookie of the socket
 */
__attribute__((always_inline)) static int trace__sock_gen_cookie_ret(struct pt_regs *ctx, u64 ret)
{
    // Check if the cookie should be resolved in a pid
    int key = 0;
    struct map_cookie_t *trace = bpf_map_lookup_elem(&map_cookie, &key);
    if (trace == NULL)
    {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid();
    bpf_printk("cookie:%u pid:%u\n", trace->cookie, pid);
    // Delete resolution request
    bpf_map_delete_elem(&map_cookie, &key);
    return 0;
};

    /**
 * Network traffic
 * ---------------
 *
 * The goal of this section is to track network traffic, assess security posture
 * and block network traffic when an attack is discovered.
 */

#define DNS_REQUEST_PARSER_KEY 0
#define DNS_RESPONSE_PARSER_KEY 1
#define CIDR_ENTRY_PROG_KEY 2

struct bpf_map_def SEC("maps/dns_prog_array") dns_prog_array = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = 4,
    .value_size = 4,
    .max_entries = 3,
};

#define NO_PROFILE_DEFAULT_ACTION ACTION_IGNORE

/**
 * Network alert struct
 */

struct bpf_map_def SEC("maps/net_alerts") net_alerts = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/dns_queries") dns_queries = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/dns_responses") dns_responses = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Per CPU array for parsing DNS queries
 */
struct bpf_map_def SEC("maps/dns_query") dns_query = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct dns_query_t),
    .max_entries = 1,
    .map_flags = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Per CPU array for parsing DNS responses
 */
struct bpf_map_def SEC("maps/dns_response") dns_response = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct dns_response_t),
    .max_entries = 1,
    .map_flags = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * DNS cache entry
 */
struct bpf_map_def SEC("maps/dns_tailcall_ctx") dns_tailcall_ctx = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct net_event_t),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/cidr_tailcall_ctx") cidr_tailcall_ctx = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct dns_response_t),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct dns_cache_entry_t
{
    u64 len;
    u64 timestamp;
};

struct bpf_map_def SEC("maps/dns_cache") dns_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct dns_cache_entry_t),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Packet ID cache
 */

struct bpf_map_def SEC("maps/packet_cache") packet_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct packet_cache_t),
    .max_entries = 2048,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/sessions") sessions = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct session_key_t),
    .value_size = sizeof(struct session_t),
    .max_entries = 1024,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/nat_entries") nat_entries = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct nat_entry_t),
    .max_entries = 1024,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * ingress_ext_cls - Handles "external" ingress hooks
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int ingress_ext_cls(struct __sk_buff *skb)
{
    // Parse packet
    struct net_event_t event = {
        .data_path = INGRESS_DATA_PATH,
        .interface_type = EXTERNAL_INTERFACE,
        .timestamp = bpf_ktime_get_ns(),
    };
    int ret = parse_packet(skb, &event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Update session
    struct session_t *session = update_session(&event);
    if (session == NULL)
    {
        return TC_ACT_OK;
    }
    // Resolve netns and pid
    ret = resolve_netns_pid(&event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Decide on the action to take
    if (assess(&event, session, skb) < 0)
    {
        if (event.action == ACTION_IGNORE)
        {
            return TC_ACT_OK;
        }
        if ((event.action & ACTION_ALERT) == ACTION_ALERT || (event.action & ACTION_PROFILE_GENERATION) == ACTION_PROFILE_GENERATION)
        {
            u32 cpu = bpf_get_smp_processor_id();
            bpf_perf_event_output(skb, &net_alerts, cpu, &event, sizeof(event));
        }
        if ((event.action & ACTION_ENFORCE) == ACTION_ENFORCE)
        {
            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
};

/**
 * egress_ext_cls - Handles "external" egress hooks
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int egress_ext_cls(struct __sk_buff *skb)
{
    // Parse packet
    struct net_event_t event = {
        .data_path = EGRESS_DATA_PATH,
        .interface_type = EXTERNAL_INTERFACE,
        .timestamp = bpf_ktime_get_ns(),
    };
    int ret = parse_packet(skb, &event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Update session
    struct session_t *session = update_session(&event);
    if (session == NULL)
    {
        return TC_ACT_OK;
    }
    // Resolve netns and pid
    ret = resolve_netns_pid(&event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Decide on the action to take
    if (assess(&event, session, skb) < 0)
    {
        if (event.action == ACTION_IGNORE)
        {
            return TC_ACT_OK;
        }
        if ((event.action & ACTION_ALERT) == ACTION_ALERT || (event.action & ACTION_PROFILE_GENERATION) == ACTION_PROFILE_GENERATION)
        {
            u32 cpu = bpf_get_smp_processor_id();
            bpf_perf_event_output(skb, &net_alerts, cpu, &event, sizeof(event));
        }
        if ((event.action & ACTION_ENFORCE) == ACTION_ENFORCE)
        {
            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
};

/**
 * ingress_cls - Handles ingress hooks
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int ingress_cls(struct __sk_buff *skb)
{
    // Parse packet
    struct net_event_t event = {
        .data_path = INGRESS_DATA_PATH,
        .interface_type = CONTAINER_INTERFACE,
        .timestamp = bpf_ktime_get_ns(),
    };
    int ret = parse_packet(skb, &event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Update session
    struct session_t *session = update_session(&event);
    if (session == NULL)
    {
        return TC_ACT_OK;
    }
    // Resolve netns and pid
    ret = resolve_netns_pid(&event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Decide on the action to take
    if (assess(&event, session, skb) < 0)
    {
        if (event.action == ACTION_IGNORE)
        {
            return TC_ACT_OK;
        }
        if ((event.action & ACTION_ALERT) == ACTION_ALERT || (event.action & ACTION_PROFILE_GENERATION) == ACTION_PROFILE_GENERATION)
        {
            u32 cpu = bpf_get_smp_processor_id();
            bpf_perf_event_output(skb, &net_alerts, cpu, &event, sizeof(event));
        }
        if ((event.action & ACTION_ENFORCE) == ACTION_ENFORCE)
        {
            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
};

/**
 * egress_cls - Handles egress hooks
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int egress_cls(struct __sk_buff *skb)
{
    u32 cpu = bpf_get_smp_processor_id();
    // Parse packet
    struct net_event_t event = {
        .data_path = EGRESS_DATA_PATH,
        .interface_type = CONTAINER_INTERFACE,
        .timestamp = bpf_ktime_get_ns(),
    };
    int ret = parse_packet(skb, &event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Update session
    struct session_t *session = update_session(&event);
    if (session == NULL)
    {
        return TC_ACT_OK;
    }
    // Resolve netns and pid
    ret = resolve_netns_pid(&event);
    if (ret < 0)
    {
        return TC_ACT_OK;
    }
    // Decide on the action to take
    if (assess(&event, session, skb) < 0)
    {
        if (event.action == ACTION_IGNORE)
        {
            return TC_ACT_OK;
        }
        if ((event.action & ACTION_ALERT) == ACTION_ALERT || (event.action & ACTION_PROFILE_GENERATION) == ACTION_PROFILE_GENERATION)
        {
            bpf_perf_event_output(skb, &net_alerts, cpu, &event, sizeof(event));
        }
        if ((event.action & ACTION_ENFORCE) == ACTION_ENFORCE)
        {
            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
};

/**
 * dns_request_tailcall - Handles a dns request tail call
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int dns_request_tailcall(struct __sk_buff *skb)
{
    u32 cpu = bpf_get_smp_processor_id();
    // Select parsed data from context
    u64 key = skb->hash;
    struct net_event_t *event = bpf_map_lookup_elem(&dns_tailcall_ctx, &key);
    if (event == NULL)
    {
        return TC_ACT_OK;
    }
    // Parse query
    struct dns_query_t query = {};
    query.event = *event;
    if (parse_dns_query(&query, skb, &event->offset) < 0)
    {
        return TC_ACT_OK;
    }
    // Decide on the action to take
    if (assess_dns_query(&query) < 0)
    {
        if (event->action == ACTION_IGNORE)
        {
            return TC_ACT_OK;
        }
        if ((event->action & ACTION_ALERT) == ACTION_ALERT || (event->action & ACTION_PROFILE_GENERATION) == ACTION_PROFILE_GENERATION || (event->action & ACTION_TRACE_DNS) == ACTION_TRACE_DNS)
        {
            bpf_perf_event_output(skb, &dns_queries, cpu, &query, sizeof(query));
        }
        if ((event->action & ACTION_ENFORCE) == ACTION_ENFORCE)
        {
            return TC_ACT_SHOT;
        }
    }
    else if ((event->action & ACTION_TRACE_DNS) == ACTION_TRACE_DNS)
    {
        bpf_perf_event_output(skb, &dns_queries, cpu, &query, sizeof(query));
    }
    return TC_ACT_OK;
}

/**
 * dns_response_tailcall - Handles a dns response tail call
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int dns_response_tailcall(struct __sk_buff *skb)
{
    u32 cpu = bpf_get_smp_processor_id();
    // Select parsed data from context
    u64 key = skb->hash;
    struct net_event_t *event = bpf_map_lookup_elem(&dns_tailcall_ctx, &key);
    if (event == NULL)
    {
        return TC_ACT_OK;
    }
    // Parse response
    struct dns_response_t response = {};
    response.event = *event;
    if (parse_dns_response(&response, skb, &event->offset) < 0)
    {
        return TC_ACT_OK;
    }
    // Decide on the action to take
    if (assess_dns_response(&response, skb) < 0)
    {
        if (event->action == ACTION_IGNORE)
        {
            return TC_ACT_OK;
        }
        if ((event->action & ACTION_ALERT) == ACTION_ALERT || (event->action & ACTION_PROFILE_GENERATION) == ACTION_PROFILE_GENERATION || (event->action & ACTION_TRACE_DNS) == ACTION_TRACE_DNS)
        {
            bpf_perf_event_output(skb, &dns_responses, cpu, &response, sizeof(response));
        }
        if ((event->action & ACTION_ENFORCE) == ACTION_ENFORCE)
        {
            return TC_ACT_SHOT;
        }
    }
    else if ((event->action & ACTION_TRACE_DNS) == ACTION_TRACE_DNS)
    {
        bpf_perf_event_output(skb, &dns_responses, cpu, &response, sizeof(response));
    }
    return TC_ACT_OK;
}

/**
 * cidr_entry_tailcall - Inserts a new CIDR entry if necessary
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int cidr_entry_tailcall(struct __sk_buff *skb)
{
    // Get context
    u32 cpu = bpf_get_smp_processor_id();
    // Select parsed data from context
    u64 key = skb->hash;
    struct dns_response_t *response = bpf_map_lookup_elem(&cidr_tailcall_ctx, &key);
    if (response == NULL)
    {
        return TC_ACT_OK;
    }
    // Insert CIDR entry for the provided cookie
    int ret = 0;
    ret = insert_cidr_entry(response, response->body.domain.cookie);
    // Check the profile if applicable
    if (response->body.domain.cookie != response->event.profile_id)
    {
        struct dns_key_t key = response->body.domain;
        key.cookie = response->event.profile_id;
        int *action = bpf_map_lookup_elem(&dns_rules, &key);
        if (action != NULL)
        {
            // Tail call to insert CIDR entry in profile CIDRs
            response->body.domain.cookie = response->event.profile_id;
            // Tail call to the cidr entry program
            int cidr_key = CIDR_ENTRY_PROG_KEY;
            bpf_tail_call(skb, &dns_prog_array, cidr_key);
        }
    }
    // Decide on the action to take
    if (ret < 0)
    {
        if (response->event.action == ACTION_IGNORE)
        {
            return TC_ACT_OK;
        }
        if ((response->event.action & ACTION_ALERT) == ACTION_ALERT || (response->event.action & ACTION_PROFILE_GENERATION) == ACTION_PROFILE_GENERATION || (response->event.action & ACTION_TRACE_DNS) == ACTION_TRACE_DNS)
        {
            bpf_perf_event_output(skb, &dns_responses, cpu, response, sizeof(*response));
        }
        if ((response->event.action & ACTION_ENFORCE) == ACTION_ENFORCE)
        {
            return TC_ACT_SHOT;
        }
    }
    else if ((response->event.action & ACTION_TRACE_DNS) == ACTION_TRACE_DNS)
    {
        bpf_perf_event_output(skb, &dns_responses, cpu, response, sizeof(*response));
    }
    return TC_ACT_OK;
}

/**
 * parse_packet - Parses a packet
 * @skb: skb structure of the packet
 * @event: pointer to a net_event_t structure to hold the parsed data
 */
__attribute__((always_inline)) static int parse_packet(struct __sk_buff *skb, struct net_event_t *event)
{
    int ret = 0;
    event->ifindex = skb->ifindex;
    // Parse L2 layer
    if (parse_l2(&event->eth, skb, &event->offset) < 0)
    {
        return -1;
    }
    // Parse L3 layer
    switch (event->eth.h_protocol)
    {
    case ETH_P_ARP:
    {
        return parse_arp(event, skb, &event->offset);
    }
    default:
    {
        ret = parse_ip(&event->ip, skb, &event->offset, event->eth.h_protocol);
        if (ret < 0)
        {
            return ret;
        }
    }
    }
    // Parse L4 layer
    ret = parse_l4(&event->trans, skb, &event->offset, event->ip.protocol);
    if (ret < 0)
    {
        return ret;
    }
    // Parse L7 layer
    ret = parse_l7(event, skb, &event->offset);
    if (ret < 0)
    {
        return ret;
    }
    return 0;
};

/**
 * update_session - Update the underlying session of the network event for monitoring purposes
 * @event: pointer to a net_event_t structure that holds the parsed data
 */
__attribute__((always_inline)) static struct session_t *update_session(struct net_event_t *event)
{
    struct session_t *session;
    struct session_key_t session_key = {};
    // Check if the packet has already been handled by another interface
    struct packet_cache_t *cached_pkt = bpf_map_lookup_elem(&packet_cache, &event->ip.packet_id);
    if (cached_pkt != NULL)
    {
        // Check if the packet_id expired
        u64 time = bpf_ktime_get_ns();
        u64 delta = time - cached_pkt->timestamp;
        if (delta < ONE_MINUTE)
        {
            // Select session
            session_key = cached_pkt->session_key;
            session = bpf_map_lookup_elem(&sessions, &session_key);
            if (session == NULL)
            {
                // Shouldn't happen. Session was lost
                return session;
            }
            // Check if nat should be resolved
            if (cached_pkt->resolve_nat == 1)
            {
                add_nat_entry(event, session);
            }
            return session;
        }
    }
    new_session_key(&session_key, event);
    // Check if the session_key already exists
    int should_resolve_nat = 0;
    session = bpf_map_lookup_elem(&sessions, &session_key);
    if (session != NULL)
    {
        // Add new packet length to the session
        // TODO: differentiate with retransmit by checking if the TCP sequence number is associated to a new packet ID.
        session->bytes_sent += event->ip.tot_len;
        // Check if a new NAT should be resolved again
        u64 time = bpf_ktime_get_ns();
        u64 delta = time - session->timestamp;
        if (delta > TEN_MINUTES)
        {
            should_resolve_nat = 1;
        }
    }
    else
    {
        should_resolve_nat = 1;
        // create session entry at &session_key
        struct session_t new_session = {
            .bytes_sent = event->ip.tot_len,
        };
        bpf_map_update_elem(&sessions, &session_key, &new_session, BPF_ANY);
        session = bpf_map_lookup_elem(&sessions, &session_key);
        if (session == NULL)
        {
            return session;
        }
    }
    // Add packet entry
    struct packet_cache_t cache_entry = {
        .resolve_nat = should_resolve_nat,
    };
    cache_entry.session_key = session_key;
    cache_entry.timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&packet_cache, &event->ip.packet_id, &cache_entry, BPF_ANY);
    cached_pkt = bpf_map_lookup_elem(&packet_cache, &event->ip.packet_id);
    if (cached_pkt == NULL)
    {
        return NULL;
    }
    // Resolve nat when necessary
    if (should_resolve_nat)
    {
        // Add nat entry to session
        add_nat_entry(event, session);
    }
    return session;
};

/**
 * resolve_netns_pid - Resolves the netns and pid (when there is one) associated to the packet
 * @event: pointer to a net_event_t structure that holds the parsed data
 */
__attribute__((always_inline)) static int resolve_netns_pid(struct net_event_t *event)
{
    struct flow_pid_key_t key = {};
    struct flow_pid_value_t *flow_pid_value;
    // Resolve netns
    struct netns_t *ns = bpf_map_lookup_elem(&ifindex_netns, &event->ifindex);
    if (ns == NULL)
    {
        return -1;
    }
    event->netns = ns->netns;
    // Resolve pid
    if (event->data_path == EGRESS_DATA_PATH)
    {
        key.netns = event->netns;
        key.addr_0 = event->ip.saddr[0];
        key.addr_1 = event->ip.saddr[1];
        key.port = event->trans.sport;
    }
    else if (event->data_path == INGRESS_DATA_PATH)
    {
        key.netns = event->netns;
        key.addr_0 = event->ip.daddr[0];
        key.addr_1 = event->ip.daddr[1];
        key.port = event->trans.dport;
    }
    else
    {
        return -1;
    }
    flow_pid_value = bpf_map_lookup_elem(&flow_pid, &key);
    if (flow_pid_value == NULL)
    {
        // Try with IP set to 0.0.0.0
        key.addr_0 = 0;
        key.addr_1 = 0;
        flow_pid_value = bpf_map_lookup_elem(&flow_pid, &key);
        if (flow_pid_value == NULL)
        {
            return 0;
        }
    }
    event->pid = flow_pid_value->pid;
    return 0;
};

/**
 * assess - Decides if the packet should be dropped or allowed.
 * @event: pointer to a net_event_t structure that holds the parsed data
 * @session: pointer to session to which the packet belongs to
 */
__attribute__((always_inline)) static int assess(struct net_event_t *event, struct session_t *session, struct __sk_buff *skb)
{
    int ret = 0;
    struct cookie_t *cookie = bpf_map_lookup_elem(&netns_profile_id, &event->netns);
    if (cookie != NULL)
    {
        event->profile_id = cookie->cookie;
    }
    else
    {
        event->alert_id |= NO_PROFILE_ALERT_ID;
        event->action |= NO_PROFILE_DEFAULT_ACTION;
        return -1;
    }
    // Select binary_id
    cookie = bpf_map_lookup_elem(&pid_binary_id, &event->pid);
    if (cookie != NULL)
    {
        event->binary_id = cookie->cookie;
    }
    // Select action to take
    int *action = bpf_map_lookup_elem(&action_rules, &event->profile_id);
    if (action != NULL)
    {
        event->action = *action;
    }
    else
    {
        // default to alert
        event->alert_id |= NO_DEFAULT_ACTION_ALERT_ID;
        event->action |= ACTION_ALERT;
    }
    // Check L3
    ret = assess_l3(event, session);
    if (ret < 0)
    {
        event->alert_id |= L3_ALERT_ID;
    }
    // Check CIDR
    ret = assess_cidr(event, session);
    if (ret < 0)
    {
        event->alert_id |= CIDR_ALERT_ID;
    }
    // Check L4
    ret = assess_l4(event, session);
    if (ret < 0)
    {
        event->alert_id |= L4_ALERT_ID;
    }
    // Check L7
    ret = assess_l7(event, session);
    if (ret < 0)
    {
        event->alert_id |= L7_ALERT_ID;
    }
    // Check network attacks
    assess_network(event, session);
    // Check DNS (insert CIDR on response)
    if (event->app.protocol == DNS_PROTOCOL)
    {
        ret = tailcall_dns(event, session, skb);
        if (ret < 0)
        {
            event->alert_id |= DNS_ALERT_ID;
        }
    }
    return -(event->alert_id != 0);
};

/**
 * assess - Assesses l3. Returns 0 if access should be granted, -1 if not.
 * @event: pointer to a net_event_t structure that holds the parsed data
 * @session: pointer to session to which the packet belongs to
 */
__attribute__((always_inline)) static int assess_l3(struct net_event_t *event, struct session_t *session)
{
    // Check l3 protocol
    struct protocol_key_t key = {};
    key.traffic_type = event->data_path;
    key.protocol = event->eth.h_protocol;
    key.layer = 3;
    if (event->pid != 0)
    {
        key.cookie = event->binary_id;
    }
    else
    {
        key.cookie = event->profile_id;
    }
    // Look for rule entry
    int *action = bpf_map_lookup_elem(&protocol_rules, &key);
    if (action == NULL)
    {
        return -1;
    }
    return 0;
};

/**
 * assess - Assesses l4. Returns 0 if access should be granted, -1 if not.
 * @event: pointer to a net_event_t structure that holds the parsed data
 * @session: pointer to session to which the packet belongs to
 */
__attribute__((always_inline)) static int assess_l4(struct net_event_t *event, struct session_t *session)
{
    // Only assess the event if a L4 protocol is provided
    if (event->ip.protocol == 0)
    {
        return 0;
    }
    // Check L4 protocol
    struct protocol_key_t key = {};
    struct protocol_port_key_t pkey = {};
    key.traffic_type = event->data_path;
    pkey.traffic_type = event->data_path;
    key.protocol = event->ip.protocol;
    pkey.protocol = event->ip.protocol;
    key.layer = 4;
    if (event->data_path == EGRESS_DATA_PATH)
    {
        pkey.port = event->trans.dport;
    }
    else if (event->data_path == INGRESS_DATA_PATH)
    {
        pkey.port = event->trans.sport;
    }
    if (event->pid != 0)
    {
        key.cookie = event->binary_id;
        pkey.cookie = event->binary_id;
    }
    else
    {
        key.cookie = event->profile_id;
        pkey.cookie = event->profile_id;
    }
    // Look for rule entry
    int *action = bpf_map_lookup_elem(&protocol_rules, &key);
    if (action != NULL)
    {
        return 0;
    }
    // Check the protocol-port rule
    action = bpf_map_lookup_elem(&protocol_port_rules, &pkey);
    if (action != NULL)
    {
        return 0;
    }
    return -1;
};

/**
 * assess - Assesses l7. Returns 0 if access should be granted, -1 if not.
 * @event: pointer to a net_event_t structure that holds the parsed data
 * @session: pointer to session to which the packet belongs to
 */
__attribute__((always_inline)) static int assess_l7(struct net_event_t *event, struct session_t *session)
{
    // Only assess the event if a L4 protocol is provided
    if (event->app.protocol == 0)
    {
        return 0;
    }
    // Check L4 protocol
    struct protocol_key_t key = {};
    key.traffic_type = event->data_path;
    key.protocol = event->app.protocol;
    key.layer = 7;
    if (event->pid != 0)
    {
        key.cookie = event->binary_id;
    }
    else
    {
        key.cookie = event->profile_id;
    }
    // Look for rule entry
    int *action = bpf_map_lookup_elem(&protocol_rules, &key);
    if (action != NULL)
    {
        return 0;
    }
    // Check if any protocol is allowed
    key.protocol = ANY_PROTOCOL;
    action = bpf_map_lookup_elem(&protocol_rules, &key);
    if (action != NULL)
    {
        return 0;
    }
    return -1;
};

struct lpm_trie_key
{
    u32 prefixlen;
    u8 data[20];
};

/**
 * assess - Assesses cidr. Returns 0 if access should be granted, -1 if not.
 * @event: pointer to a net_event_t structure that holds the parsed data
 * @session: pointer to session to which the packet belongs to
 */
__attribute__((always_inline)) static int assess_cidr(struct net_event_t *event, struct session_t *session)
{
    // Check if event is an IPv4 or IPv6 event
    if ((event->eth.h_protocol != ETH_P_IP) && (event->eth.h_protocol != ETH_P_IPV6))
    {
        return 0;
    }
    // select the right LPM_TRIE map
    struct cidr_rule_t key = {};
    key.protocol = event->eth.h_protocol;
    key.traffic_type = event->data_path;
    if (event->pid != 0)
    {
        key.cookie = event->binary_id;
    }
    else
    {
        key.cookie = event->profile_id;
    }
    void *cidr_range = bpf_map_lookup_elem(&cidr_rules, &key);
    if (cidr_range == NULL)
    {
        return -1;
    }
    // Look for detected IP
    struct lpm_trie_key ip_key = {};
    switch (event->eth.h_protocol)
    {
    case ETH_P_IP:
        ip_key.prefixlen = 32;
        break;
    case ETH_P_IPV6:
        ip_key.prefixlen = 128;
        break;
    default:
        return -1;
    }
    switch (event->data_path)
    {
    case EGRESS_DATA_PATH:
#pragma unroll
        for (int i = 0; i < 9; i++)
        {
            ip_key.data[i] = event->ip.daddr[(i >= 8)] >> 8 * (i % 8);
        }
        break;
    case INGRESS_DATA_PATH:
#pragma unroll
        for (int i = 0; i < 9; i++)
        {
            ip_key.data[i] = event->ip.saddr[(i >= 8)] >> 8 * (i % 8);
        }
        break;
    default:
        return -1;
    }
    int *value = bpf_map_lookup_elem(cidr_range, &ip_key);
    if (value == NULL)
    {
        return -1;
    }
    return 0;
};

/**
 * assess_dns_query - Assesses a DNS query. Returns 0 if access should be granted, -1 if not.
 * @query: pointer to a dns_query_t structure that holds the parsed data
 */
__attribute__((always_inline)) static int assess_dns_query(struct dns_query_t *query)
{
    // Assess A and AAAA queries only
    if (query->body.qtype != DNS_A_RECORD && query->body.qtype != DNS_AAAA_RECORD)
    {
        return TC_ACT_OK;
    }
    query->body.domain.traffic_type = EGRESS_DATA_PATH;
    query->body.domain.layer = 7;
    if (query->event.pid != 0)
    {
        query->body.domain.cookie = query->event.binary_id;
    }
    else
    {
        query->body.domain.cookie = query->event.profile_id;
    }
    // Look for rule entry
    int *action = bpf_map_lookup_elem(&dns_rules, &query->body.domain);
    if (action == NULL)
    {
        query->event.alert_id |= DNS_ALERT_ID;
    }
    return -(query->event.alert_id != 0);
}

/**
 * assess_dns_response - Assesses a DNS response. Returns 0 if access should be granted, -1 if not.
 * @response: pointer to a dns_response_t structure that holds the parsed data
 */
__attribute__((always_inline)) static int assess_dns_response(struct dns_response_t *response, struct __sk_buff *skb)
{
    // Assess A and AAAA queries only
    if (response->body.type != DNS_A_RECORD && response->body.type != DNS_AAAA_RECORD)
    {
        return TC_ACT_OK;
    }
    response->body.domain.traffic_type = EGRESS_DATA_PATH;
    response->body.domain.layer = 7;
    if (response->event.pid != 0)
    {
        response->body.domain.cookie = response->event.binary_id;
    }
    else
    {
        response->body.domain.cookie = response->event.profile_id;
    }
    // Look for rule entry
    int *action = bpf_map_lookup_elem(&dns_rules, &response->body.domain);
    if (action == NULL)
    {
        response->event.alert_id |= DNS_ALERT_ID;
        return -(response->event.alert_id != 0);
    }
    // Check if CIDR entry should be added
    response->body.domain.layer = 3;
    action = bpf_map_lookup_elem(&dns_rules, &response->body.domain);
    if (action != NULL)
    {
        // Save context
        u64 key = skb->hash;
        bpf_map_update_elem(&cidr_tailcall_ctx, &key, response, BPF_ANY);
        // Tail call to the cidr entry program
        int cidr_key = CIDR_ENTRY_PROG_KEY;
        bpf_tail_call(skb, &dns_prog_array, cidr_key);
    }
    return -(response->event.alert_id != 0);
}

/**
 * insert_cidr_entry - Inserts a CIDR entry for the provided DNS response. Returns 0 if access should be granted, -1 if not.
 * @response: pointer to a dns_response_t structure that holds the parsed data
 */
__attribute__((always_inline)) static int insert_cidr_entry(struct dns_response_t *response, u32 cookie)
{
    // select the EGRESS LPM_TRIE map
    struct cidr_rule_t key = {};
    key.protocol = response->event.eth.h_protocol;
    key.traffic_type = EGRESS_DATA_PATH;
    key.cookie = cookie;
    void *cidr_range = bpf_map_lookup_elem(&cidr_rules, &key);
    if (cidr_range == NULL)
    {
        return -1;
    }
    // Prepare IP key
    struct lpm_trie_key ip_key = {};
    switch (response->event.eth.h_protocol)
    {
    case ETH_P_IP:
        ip_key.prefixlen = 32;
        break;
    case ETH_P_IPV6:
        ip_key.prefixlen = 128;
        break;
    default:
        return -1;
    }
#pragma unroll
    for (int i = 0; i < 9; i++)
    {
        ip_key.data[i] = response->body.addr[(i >= 8)] >> 8 * (i % 8);
    }
    u64 value = 0;
    bpf_map_update_elem(cidr_range, &ip_key, &value, BPF_ANY);
    // Insert the INGRESS counterpart
    key.traffic_type = INGRESS_DATA_PATH;
    cidr_range = bpf_map_lookup_elem(&cidr_rules, &key);
    if (cidr_range == NULL)
    {
        return -1;
    }
    bpf_map_update_elem(cidr_range, &ip_key, &value, BPF_ANY);
    return 0;
}

/**
 * tailcall_dns - Tail calls to the right DNS program. Returns 0 if access should be granted, -1 if not.
 * @event: pointer to a net_event_t structure that holds the parsed data
 * @session: pointer to session to which the packet belongs to
 */
__attribute__((always_inline)) static int tailcall_dns(struct net_event_t *event, struct session_t *session, struct __sk_buff *skb)
{
    // Save event context
    u64 key = skb->hash;
    bpf_map_update_elem(&dns_tailcall_ctx, &key, event, BPF_ANY);
    if (event->trans.dport == 53)
    {
        // Tail call to the dns request parser
        int parser_key = DNS_REQUEST_PARSER_KEY;
        bpf_tail_call(skb, &dns_prog_array, parser_key);
    }
    else if (event->trans.sport == 53)
    {
        // Tail call to the dns response parser
        int parser_key = DNS_RESPONSE_PARSER_KEY;
        bpf_tail_call(skb, &dns_prog_array, parser_key);
    }
    return -1;
};

/**
 * assess - Assesses network. Returns 0 if access should be granted, -1 if not.
 * @event: pointer to a net_event_t structure that holds the parsed data
 * @session: pointer to session to which the packet belongs to
 */
__attribute__((always_inline)) static void assess_network(struct net_event_t *event, struct session_t *session)
{
    // Select Network Attacks flag
    // Assess each attack
    return;
};

/**
 * new_session_key - Populates the provided session_key with the data from the provided event
 * @session_key: session key to populate
 * @event: pointer to a net_event_t structure to hold the parsed data
 */
__attribute__((always_inline)) static void new_session_key(struct session_key_t *session_key, struct net_event_t *event)
{
    session_key->ifindex = event->ifindex;
    session_key->daddr[0] = event->ip.daddr[0];
    session_key->daddr[1] = event->ip.daddr[1];
    session_key->saddr[0] = event->ip.saddr[0];
    session_key->saddr[1] = event->ip.saddr[1];
    session_key->h_protocol = event->eth.h_protocol;
    session_key->protocol = event->ip.protocol;
    session_key->sport = event->trans.sport;
    session_key->dport = event->trans.dport;
    session_key->data_path = event->data_path;
};

/**
 * add_nat_entry - Add a nat entry to the session
 * @event: pointer to a net_event_t structure to hold the parsed data
 * @session: session to which the nat entry should be added
 */
__attribute__((always_inline)) static void add_nat_entry(struct net_event_t *event, struct session_t *session)
{
    struct nat_entry_t entry = {};
    entry.ifindex = event->ifindex;
    entry.daddr[0] = event->ip.daddr[0];
    entry.daddr[1] = event->ip.daddr[1];
    entry.saddr[0] = event->ip.saddr[0];
    entry.saddr[1] = event->ip.saddr[1];
    entry.sport = event->trans.sport;
    entry.dport = event->trans.dport;
#pragma unroll
    for (int i = 0; i < 6; i++)
    {
        entry.h_dest[i] = event->eth.h_dest[i];
    }
#pragma unroll
    for (int i = 0; i < 6; i++)
    {
        entry.h_source[i] = event->eth.h_source[i];
    }
    entry.next_nat_key = bpf_get_prandom_u32();
    // Add nat entry
    u32 key = session->next_nat_key;
    bpf_map_update_elem(&nat_entries, &key, &entry, BPF_ANY);
    // Update session with the new nat key
    session->next_nat_key = entry.next_nat_key;
};

/**
  * parse_l2 - Parses sk_buff to retrieve L2 data. Returns 0 on success, negative value on error.
  */
__attribute__((always_inline)) static int parse_l2(struct ethernet_h_t *h, struct __sk_buff *skb, int *offset)
{
    if (bpf_skb_load_bytes(skb, 0, &h->h_dest, ETH_ALEN) < 0)
    {
        return -1;
    }
    if (bpf_skb_load_bytes(skb, ETH_ALEN, &h->h_source, ETH_ALEN) < 0)
    {
        return -1;
    }
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h->h_protocol, sizeof(h->h_protocol)) < 0)
    {
        return -1;
    }
    h->h_protocol = be16_to_cpu(h->h_protocol);
    *offset = ETH_HLEN;
    return 0;
};

/**
  * parse_ip - Parses sk_buff to retrieve L3 data. Returns 0 on success, negative value on error.
  */
__attribute__((always_inline)) static int parse_ip(struct ip_h_t *h, struct __sk_buff *skb, int *offset, int h_protocol)
{
    switch (h_protocol)
    {
    case ETH_P_IP:
    {
        h->ip_version = 4;
        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, *offset, &iph, sizeof(iph)) < 0)
        {
            return -1;
        }
        h->protocol = iph.protocol;
        h->saddr[0] = iph.saddr;
        h->daddr[0] = iph.daddr;
        h->tot_len = be16_to_cpu(iph.tot_len);
        h->packet_id = iph.id;
        h->frag_off = iph.frag_off;
        *offset += sizeof(iph);
        return 0;
    }
    case ETH_P_IPV6: // Handle IPv6
    {
        h->ip_version = 6;
        struct ipv6hdr iph;
        if (bpf_skb_load_bytes(skb, *offset, &iph, sizeof(iph)) < 0)
        {
            return -1;
        }
        h->protocol = iph.nexthdr;
        h->tot_len = be16_to_cpu(iph.payload_len);
        h->frag_off = 0;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, saddr), &h->saddr, sizeof(h->saddr)) < 0)
        {
            return -1;
        }
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, daddr), &h->saddr, sizeof(h->daddr)) < 0)
        {
            return -1;
        }
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, flow_lbl), &h->packet_id, sizeof(iph.flow_lbl)) < 0)
        {
            return -1;
        }
        *offset += sizeof(iph);
        return 0;
    }
    default:
    {
        // TODO: support more protocols
        return 0;
    }
    }
};

/**
  * parse_arp - Parses arp header. Returns 0 on success, a negative value on error.
  */
__attribute__((always_inline)) static int parse_arp(struct net_event_t *h, struct __sk_buff *skb, int *offset)
{
    struct arp_h_t arp = {};
    if (bpf_skb_load_bytes(skb, *offset, &arp, sizeof(struct arp_h_t)) < 0)
    {
        return -1;
    }
    arp.ar_op = be16_to_cpu(arp.ar_op);
    *offset += sizeof(struct arp_h_t);
    return 0;
};

/**
  * parse_l4 - Parses sk_buff to retrieve L4 data. Returns 0 on success, negative value on error.
  */
__attribute__((always_inline)) static int parse_l4(struct transport_h_t *h, struct __sk_buff *skb, int *offset, int protocol)
{
    switch (protocol)
    {
    case IPPROTO_ICMP:
    {
        h->sport = 0;
        h->dport = 0;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct icmphdr, type), &h->flags, sizeof(__u8)) < 0)
        {
            return -1;
        }
        *offset += sizeof(struct icmphdr);
        return 0;
    }
    case IPPROTO_ICMPV6: // Handle IPv6
    {
        h->sport = 0;
        h->dport = 0;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct icmp6hdr, icmp6_type), &h->flags, sizeof(__u8)) < 0)
        {
            return -1;
        }
        *offset += sizeof(struct icmp6hdr);
        return 0;
    }
    case IPPROTO_TCP:
    {
        struct tcphdr tcphdr;
        if (bpf_skb_load_bytes(skb, *offset, &tcphdr, sizeof(struct tcphdr)) < 0)
        {
            return -1;
        }
        h->sport = be16_to_cpu(tcphdr.source);
        h->dport = be16_to_cpu(tcphdr.dest);
        h->flags = tcphdr.fin + (tcphdr.syn << 1) + (tcphdr.rst << 2) + (tcphdr.psh << 3) + (tcphdr.ack << 4) + (tcphdr.urg << 5) + (tcphdr.ece << 6) + (tcphdr.cwr << 7);
        *offset += sizeof(struct tcphdr);
        return 0;
    }
    case IPPROTO_UDP:
    {
        struct udphdr udphdr;
        if (bpf_skb_load_bytes(skb, *offset, &udphdr, sizeof(struct udphdr)) < 0)
        {
            return -1;
        }
        h->sport = be16_to_cpu(udphdr.source);
        h->dport = be16_to_cpu(udphdr.dest);
        *offset += sizeof(struct udphdr);
        return 0;
    }
    case IPPROTO_SCTP:
    {
        struct sctphdr sctphdr;
        if (bpf_skb_load_bytes(skb, *offset, &sctphdr, sizeof(struct sctphdr)) < 0)
        {
            return -1;
        }
        h->sport = be16_to_cpu(sctphdr.source);
        h->dport = be16_to_cpu(sctphdr.dest);
        *offset += sizeof(struct sctphdr);
        return 0;
    }
    default:
    {
        // TODO: Add support for more protocols: IPPROTO_SCTP, ...
        return 0;
    }
    }
};

/**
  * parse_l7 - Parses sk_buff to retrieve L7 data. Returns 0 on success, negative value on error.
  */
__attribute__((always_inline)) static int parse_l7(struct net_event_t *event, struct __sk_buff *skb, int *offset)
{
    if ((event->trans.dport == 53) || (event->trans.sport == 53))
    {
        event->app.protocol = DNS_PROTOCOL;
    }
    else if ((event->trans.dport == 80) || (event->trans.sport == 80))
    {
        event->app.protocol = HTTP_PROTOCOL;
    }
    else if ((event->trans.dport == 443) || (event->trans.sport == 443))
    {
        event->app.protocol = HTTPS_PROTOCOL;
    }
    return 0;
};

/**
  * parse_dns_query - Parses sk_buff to retrieve DNS query data. Returns 0 on success, negative value on error.
  */
__attribute__((always_inline)) static int parse_dns_query(struct dns_query_t *h, struct __sk_buff *skb, int *offset)
{
    if (bpf_skb_load_bytes(skb, *offset, &h->header, sizeof(h->header)) < 0)
    {
        return -1;
    }
    *offset += 12;
    // Calculate and parse qname length
    int qname_length = skb->len - (*offset + 4);
    // (qname_length & (DNS_MAX_LENGTH - 1)) | 1) => required for the verifier
    if (bpf_skb_load_bytes(skb, *offset, &h->body.domain.name, (qname_length & (DNS_MAX_LENGTH - 1)) | 1) < 0)
    {
        return -1;
    }
    *offset += qname_length;
    // Handle qtype
    if (bpf_skb_load_bytes(skb, *offset, &h->body.qtype, sizeof(u16)) < 0)
    {
        return -1;
    }
    h->body.qtype = be16_to_cpu(h->body.qtype);
    *offset += sizeof(u16);
    // Handle qclass
    if (bpf_skb_load_bytes(skb, *offset, &h->body.qclass, sizeof(u16)) < 0)
    {
        return -1;
    }
    h->body.qclass = be16_to_cpu(h->body.qclass);
    *offset += sizeof(u16);
    // Cache name length
    struct dns_cache_entry_t entry = {
        .len = qname_length,
        .timestamp = bpf_ktime_get_ns(),
    };
    int key = h->header.id;
    bpf_map_update_elem(&dns_cache, &key, &entry, BPF_ANY);
    return 0;
};

#define COMPRESSION_FLAG 3

/**
  * parse_dns_response - Parses sk_buff to retrieve DNS response data. Returns 0 on success, negative value on error.
  */
__attribute__((always_inline)) static int parse_dns_response(struct dns_response_t *h, struct __sk_buff *skb, int *offset)
{
    if (bpf_skb_load_bytes(skb, *offset, &h->header, sizeof(h->header)) < 0)
    {
        return -1;
    }
    *offset += sizeof(h->header);
    // Only parse the first DNS answer, if it is a A or AAAA answer. We are not dealing with the other potential
    // answers for now, although it could be done using tail calls of eBPF programs. There is a maximum of 25 dns
    // answers per dns response.
    // https://stackoverflow.com/questions/6794926/how-many-a-records-can-fit-in-a-single-dns-response
    int key = h->header.id;
    struct dns_cache_entry_t *entry = bpf_map_lookup_elem(&dns_cache, &key);
    if (entry == NULL)
    {
        return -1;
    }
    h->query_timestamp = entry->timestamp;
    // Parse qname
    if (bpf_skb_load_bytes(skb, *offset, &h->body.domain.name, (entry->len & (DNS_MAX_LENGTH - 1)) | 1) < 0)
    {
        return -1;
    }
    // Jump to begining of response (jump QName + QType + QClass of the question part)
    *offset += entry->len + 2 * sizeof(u16);
    // Check if packet compression is used
    u8 compression = 0;
    if (bpf_skb_load_bytes(skb, *offset, &compression, 1) < 0)
    {
        return -1;
    }
    if ((compression >> 6) == COMPRESSION_FLAG)
    {
        // Find first A or AAAA response
#pragma unroll
        for (int i = 0; i < 4; i++)
        {
            // Jump DNS packet compression offset.
            *offset += sizeof(u16);
            // Parse type
            if (bpf_skb_load_bytes(skb, *offset, &h->body.type, sizeof(u16)) < 0)
            {
                return -1;
            }
            h->body.type = be16_to_cpu(h->body.type);
            *offset += sizeof(u16);
            if (h->body.type == DNS_A_RECORD || h->body.type == DNS_AAAA_RECORD)
            {
                break;
            }
            // Jump type, class, ttl
            *offset += sizeof(u16) * 3;
            // Parse length
            if (bpf_skb_load_bytes(skb, *offset, &h->body.rdlength, sizeof(u16)) < 0)
            {
                return -1;
            }
            h->body.rdlength = be16_to_cpu(h->body.rdlength);
            // Jump length + rdata
            *offset += sizeof(u16) + h->body.rdlength;
        }
    }
    else
    {
        // Jump Name section
        *offset += entry->len;
        // Parse type
        if (bpf_skb_load_bytes(skb, *offset, &h->body.type, sizeof(u16)) < 0)
        {
            return -1;
        }
        h->body.type = be16_to_cpu(h->body.type);
        *offset += sizeof(u16);
    }
    // Handle class, ttl and rdlength
    if (bpf_skb_load_bytes(skb, *offset, &h->body.class, sizeof(u16)) < 0)
    {
        return -1;
    }
    h->body.class = be16_to_cpu(h->body.class);
    *offset += sizeof(u16);
    if (bpf_skb_load_bytes(skb, *offset, &h->body.ttl, sizeof(u32)) < 0)
    {
        return -1;
    }
    // h->body.ttl = be32_to_cpu(h->body.ttl);
    *offset += sizeof(u32);
    if (bpf_skb_load_bytes(skb, *offset, &h->body.rdlength, sizeof(u16)) < 0)
    {
        return -1;
    }
    h->body.rdlength = be16_to_cpu(h->body.rdlength);
    *offset += sizeof(u16);
    // Only parse IPv4 and IPv6 addresses. TODO: add support for CNAME, ...
    switch (h->body.rdlength)
    {
    case 4:
    {
        if (bpf_skb_load_bytes(skb, *offset, &h->body.addr, sizeof(u32)) < 0)
        {
            return -1;
        }
        return 0;
    }
    case 16:
    {
        if (bpf_skb_load_bytes(skb, *offset, &h->body.addr, 2 * sizeof(u64)) < 0)
        {
            return -1;
        }
        return 0;
    }
    default:
        return 0;
    }
};

/**
 * Tools
 */

/**
 * netns_from_device - Returns the netns of a device
 * @dev: device
 */
__attribute__((always_inline)) static u64 netns_from_device(struct net_device *dev)
{
    possible_net_t *skc_net = &dev->nd_net;
    struct net *net;
    bpf_probe_read(&net, sizeof(struct net *), &skc_net->net);
    struct ns_common *ns = &net->ns;
    u64 inum;
    bpf_probe_read(&inum, sizeof(inum), &ns->inum);
    return inum;
};

/**
 * device_from_net_device - Returns a device_t instance from a net_device instance
 * @dev: device
 */
__attribute__((always_inline)) static void device_from_net_device(struct net_device *netdev, struct device_t *dev)
{
    dev->netns = netns_from_device(netdev);
    bpf_probe_read(&dev->ifindex, sizeof(dev->ifindex), &netdev->ifindex);
    bpf_probe_read(&dev->group, sizeof(dev->group), &netdev->group);
    bpf_probe_read(&dev->name, IFNAMSIZ, &netdev->name);
};

/**
 * cgroup_ingress - Handles cgroup ingress hook
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int cgroup_ingress(struct __sk_buff *skb)
{
    u32 ifindex = skb->ifindex;
    if (ifindex == 2)
    {
        return 1;
    }
    // Get cookie and ask sock_gen_cookie kretprobe to record the owner pid
    int key = 0;
    u32 cookie = bpf_get_socket_cookie(skb);
    struct map_cookie_t value = {
        .cookie = cookie,
    };
    bpf_map_update_elem(&map_cookie, &key, &value, BPF_ANY);
    bpf_get_socket_cookie(skb);

    struct iphdr iph;
    bpf_skb_load_bytes(skb, 0, &iph, 12);
    void *data = (void *)skb + offsetof(struct __sk_buff, data) - sizeof(struct ethhdr);
    bpf_printk("=> CGROUP ifindex:%d cookie:%u pkt_id:%d\n", ifindex, cookie, iph.id);
    bpf_printk("   data:%p skb:%p\n", data, skb);
    return 1;
};

/**
 * cgroup_egress - Handles cgroup egress hook
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int cgroup_egress(struct __sk_buff *skb)
{
    u32 ifindex = skb->ifindex;
    if (ifindex == 2)
    {
        return 1;
    }
    // Get cookie and ask sock_gen_cookie kretprobe to record the owner pid
    int key = 0;
    u32 cookie = bpf_get_socket_cookie(skb);
    struct map_cookie_t value = {
        .cookie = cookie,
    };
    bpf_map_update_elem(&map_cookie, &key, &value, BPF_ANY);
    bpf_get_socket_cookie(skb);

    struct iphdr iph;
    bpf_skb_load_bytes(skb, 0, &iph, 12);
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(struct ethhdr));
    void *data = (void *)skb + offsetof(struct __sk_buff, data) - sizeof(struct ethhdr);
    bpf_printk("<= CGROUP ifindex:%d cookie:%u pkt_id:%d\n", ifindex, cookie, iph.id);
    eth.h_proto = be16_to_cpu(eth.h_proto);
    bpf_printk("   data:%p skb:%p h_protocol:%d\n", data, skb, eth.h_proto);
    return 1;
};

/**
 * cgroup_sock - Handles cgroup sock creation hook
 * @skb: skb structure of the packet
 */
__attribute__((always_inline)) static int cgroup_sock(struct bpf_sock *sk)
{
    bpf_printk("socket - family:%d type:%d protocol:%d\n", sk->family, sk->type, sk->protocol);

    /* block PF_INET, SOCK_RAW, IPPROTO_ICMP sockets
	 * ie., make ping fail
	 */
    if (sk->family == PF_INET &&
        sk->type == SOCK_RAW &&
        sk->protocol == IPPROTO_ICMP)
        return 1;

    return 1;
};

/**
 * Process
 * -------
 *
 * The goal of this section is to track process exec and fork events.
 */

/**
 * Forck cache struct
 */

struct fork_t
{
    struct metadata_t metadata;
    u64 clone_flags;
    u64 stack_start;
    u64 stack_size;
    pid_t child_pid;
};

struct bpf_map_def SEC("maps/fork_cache") fork_cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(struct fork_t),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/fork_events") fork_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * Per CPU array for tracking exec events
 */
struct bpf_map_def SEC("maps/exec_path") exec_path = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct exec_path_key_t),
    .max_entries = 1,
    .map_flags = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

#define EXECVE_TYPE 0
#define EXIT_TYPE 1

struct exec_event_t
{
    struct metadata_t metadata;
    u32 type;
    struct exec_path_key_t path;
};

struct bpf_map_def SEC("maps/exec_events") exec_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/**
 * trace__do_fork - Handles _do_fork kprobe hook
 * @clone_flags: flags of the clone call
 * @stack_start: start addr of the stack in memory
 * @stack_size: stack size
 */
__attribute__((always_inline)) static int trace__do_fork(unsigned long clone_flags,
                                                         unsigned long stack_start,
                                                         unsigned long stack_size)
{
    struct fork_t event = {};
    // Process metadata
    u64 key = fill_metadata(&event.metadata);
    event.clone_flags = clone_flags;
    event.stack_start = stack_start;
    event.stack_size = stack_size;

    // Cache fork event
    bpf_map_update_elem(&fork_cache, &key, &event, BPF_ANY);
    return 0;
};

/**
 * trace_sched_process_fork - Handles fork tracepoint hook
 * @child_pid: child pid
 */
__attribute__((always_inline)) static int trace__sched_sched_process_fork(struct sched_process_fork_args *ctx, pid_t child_pid)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 binary_id = 0;
    u32 key = bpf_get_current_pid_tgid();
    struct fork_t *event = bpf_map_lookup_elem(&fork_cache, &key);
    if (!event)
        return 0;

    // Only duplicate binary_id entry if this is the creation of a new process
    if ((event->clone_flags & SIGCHLD) != SIGCHLD)
        goto exit;
    // Get binary_id of parent
    struct cookie_t *cookie = bpf_map_lookup_elem(&pid_binary_id, &key);
    if (cookie == NULL)
        goto exit;
    // Duplicate entry for child pid
    binary_id = cookie->cookie;
    bpf_map_update_elem(&pid_binary_id, &child_pid, &binary_id, BPF_ANY);
    goto exit;
exit:
    // bpf_printk("child_pid:%u cookie:%u\n", child_pid, binary_id);
    bpf_map_delete_elem(&fork_cache, &key);
    event->child_pid = child_pid;
    bpf_perf_event_output(ctx, &fork_events, cpu, event, sizeof(*event));
    return 0;
};

/**
 * trace_sched_process_exec - Handles exec tracepoint hook
 * @args: pointer to tracepoint arguments
 */
__attribute__((always_inline)) static int trace__sched_sched_process_exec(struct sched_process_exec_args *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();
    unsigned short __offset = ctx->data_loc_filename & 0xFFFF;
    char *filename = (char *)ctx + __offset;
    struct exec_event_t event = {};
    bpf_probe_read_str(&event.path.filename, PATH_MAX_LEN, filename);
    fill_metadata(&event.metadata);
    // Fetch profile cookie
    struct cookie_t *cookie = bpf_map_lookup_elem(&netns_profile_id, &event.metadata.netns);
    if (cookie != NULL)
    {
        // Fetch process cookie
        event.path.cookie = cookie->cookie;
        cookie = bpf_map_lookup_elem(&path_binary_id, &event.path);
        if (cookie == NULL)
        {
            u32 void_cookie = 0;
            bpf_map_update_elem(&pid_binary_id, &event.metadata.pid, &void_cookie, BPF_ANY);
            goto exit;
        }
        // Save binary_id for this process
        // We have to create a new instance of cookie because you can't use a pointer to an
        // existing map value as the value of another map ...
        // See https://github.com/iovisor/bcc/issues/347
        struct cookie_t binary_id_value = {
            .cookie = cookie->cookie,
        };
        bpf_map_update_elem(&pid_binary_id, &event.metadata.pid, &binary_id_value, BPF_ANY);
        goto exit;
    }
    u32 void_cookie = 0;
    bpf_map_update_elem(&pid_binary_id, &event.metadata.pid, &void_cookie, BPF_ANY);
exit:
    event.type = EXECVE_TYPE;
    bpf_perf_event_output(ctx, &exec_events, cpu, &event, sizeof(event));
    return 0;
};

/**
 * trace_sched_process_exit - Handles exit tracepoint hook
 * @args: pointer to tracepoint arguments
 */
__attribute__((always_inline)) static int trace__sched_sched_process_exit(struct sched_process_exit_args *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct exec_event_t event = {};
    fill_metadata(&event.metadata);
    event.type = EXIT_TYPE;
    bpf_perf_event_output(ctx, &exec_events, cpu, &event, sizeof(event));
    return 0;
};
