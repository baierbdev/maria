#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/timekeeping.h>

#include "packet_protocol.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bruno & Maria IDS Project");
MODULE_DESCRIPTION("LKM packet sniffer using dev_add_pack and Netlink streaming");
MODULE_VERSION("1.0");

static bool capture_loopback = false;
module_param(capture_loopback, bool, 0644);
MODULE_PARM_DESC(capture_loopback, "Capture loopback interface packets (default: false)");

static int nl_unit = MARIA_NL_UNIT;
module_param(nl_unit, int, 0644);
MODULE_PARM_DESC(nl_unit, "Netlink unit number (default: 2 / NETLINK_USERSOCK)");

static struct sock *maria_nl_sock = NULL;
static atomic_t user_pid = ATOMIC_INIT(0);

/* Packet receive callback invoked directly by kernel packet type handler */
static int maria_packet_rcv(struct sk_buff *skb, struct net_device *dev,
                            struct packet_type *pt, struct net_device *orig_dev)
{
    u32 pid;
    struct iphdr ip_header;
    const struct iphdr *iph;
    int ip_hlen;
    u16 src_port = 0, dst_port = 0;
    u8 tcp_flags = 0;
    int payload_offset = 0;
    int payload_len = 0;
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;
    struct maria_nl_msg *msg;
    int ret;

    if (!skb)
        return NET_RX_SUCCESS;

    pid = atomic_read(&user_pid);
    if (!pid || !maria_nl_sock) {
        /* No user space daemon listening; release tap reference and return */
        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

    /* Filter loopback if disabled */
    if (!capture_loopback && dev && (dev->flags & IFF_LOOPBACK)) {
        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

    /* Ensure skb has at least IPv4 header length */
    if (skb->len < sizeof(struct iphdr)) {
        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

    /* Safely access IPv4 header */
    iph = skb_header_pointer(skb, 0, sizeof(ip_header), &ip_header);
    if (!iph || iph->version != 4 || iph->ihl < 5) {
        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

    ip_hlen = iph->ihl * 4;
    payload_offset = ip_hlen;

    /* Parse L4 transport layer */
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr tcp_header;
        const struct tcphdr *tcph;

        tcph = skb_header_pointer(skb, ip_hlen, sizeof(tcp_header), &tcp_header);
        if (tcph && tcph->doff >= 5) {
            src_port = ntohs(tcph->source);
            dst_port = ntohs(tcph->dest);
            tcp_flags = (tcph->fin ? MARIA_TCP_FIN : 0) |
                        (tcph->syn ? MARIA_TCP_SYN : 0) |
                        (tcph->rst ? MARIA_TCP_RST : 0) |
                        (tcph->psh ? MARIA_TCP_PSH : 0) |
                        (tcph->ack ? MARIA_TCP_ACK : 0) |
                        (tcph->urg ? MARIA_TCP_URG : 0);
            payload_offset = ip_hlen + (tcph->doff * 4);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr udp_header;
        const struct udphdr *udph;

        udph = skb_header_pointer(skb, ip_hlen, sizeof(udp_header), &udp_header);
        if (udph) {
            src_port = ntohs(udph->source);
            dst_port = ntohs(udph->dest);
            payload_offset = ip_hlen + sizeof(struct udphdr);
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        payload_offset = ip_hlen + sizeof(struct icmphdr);
    }

    /* Calculate payload length */
    if (skb->len > payload_offset) {
        payload_len = skb->len - payload_offset;
        if (payload_len > MARIA_MAX_PAYLOAD)
            payload_len = MARIA_MAX_PAYLOAD;
    }

    /* Allocate Netlink skb buffer */
    nl_skb = nlmsg_new(sizeof(struct maria_nl_msg), GFP_ATOMIC);
    if (!nl_skb) {
        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

    nlh = nlmsg_put(nl_skb, 0, 0, NLMSG_DONE, sizeof(struct maria_nl_msg), 0);
    if (!nlh) {
        nlmsg_free(nl_skb);
        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, sizeof(*msg));
    msg->type = MARIA_MSG_PACKET;
    msg->len = sizeof(struct maria_packet_data);
    msg->data.pkt.timestamp_ns = ktime_get_real_ns();
    msg->data.pkt.src_ip = iph->saddr;
    msg->data.pkt.dst_ip = iph->daddr;
    msg->data.pkt.src_port = src_port;
    msg->data.pkt.dst_port = dst_port;
    msg->data.pkt.protocol = iph->protocol;
    msg->data.pkt.tcp_flags = tcp_flags;
    msg->data.pkt.total_len = ntohs(iph->tot_len);
    msg->data.pkt.payload_len = payload_len;

    if (dev)
        strscpy(msg->data.pkt.ifname, dev->name, sizeof(msg->data.pkt.ifname));

    if (payload_len > 0)
        skb_copy_bits(skb, payload_offset, msg->data.pkt.payload, payload_len);

    ret = nlmsg_unicast(maria_nl_sock, nl_skb, pid);
    if (ret < 0) {
        if (ret == -ECONNREFUSED || ret == -ESRCH) {
            pr_info("maria: User space daemon disconnected (code: %d). Resetting PID.\n", ret);
            atomic_set(&user_pid, 0);
        }
    }

    /* Release tap reference on the skb */
    kfree_skb(skb);
    return NET_RX_SUCCESS;
}

/* Packet type hook configuration */
static struct packet_type maria_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_IP), /* Intercept IPv4 packets */
    .func = maria_packet_rcv,      /* Direct sk_buff receive callback */
    .dev = NULL,                   /* Catch packets across all interfaces */
};

/* Netlink receive handler for incoming control messages from user space */
static void maria_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct maria_nl_msg *msg;
    u32 client_pid;

    if (!skb)
        return;

    nlh = (struct nlmsghdr *)skb->data;
    if (!nlh || skb->len < NLMSG_HDRLEN || !NLMSG_OK(nlh, skb->len))
        return;

    client_pid = nlh->nlmsg_pid;
    msg = (struct maria_nl_msg *)NLMSG_DATA(nlh);
    if (!msg)
        return;

    switch (msg->type) {
    case MARIA_MSG_REGISTER:
        atomic_set(&user_pid, client_pid);
        pr_info("maria: Registered user-space daemon with PID %u\n", client_pid);
        break;

    case MARIA_MSG_UNREGISTER:
        if (atomic_read(&user_pid) == client_pid) {
            atomic_set(&user_pid, 0);
            pr_info("maria: Unregistered user-space daemon PID %u\n", client_pid);
        }
        break;

    case MARIA_MSG_HEARTBEAT:
        pr_debug("maria: Heartbeat received from PID %u\n", client_pid);
        break;

    default:
        pr_warn("maria: Unknown message type received: %u\n", msg->type);
        break;
    }
}

static int __init maria_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = maria_nl_recv_msg,
    };

    pr_info("maria: Initializing module (dev_add_pack + Netlink unit %d)...\n", nl_unit);

    maria_nl_sock = netlink_kernel_create(&init_net, nl_unit, &cfg);
    if (!maria_nl_sock) {
        pr_err("maria: Failed to create Netlink socket unit %d\n", nl_unit);
        return -ENOMEM;
    }

    dev_add_pack(&maria_packet_type);
    pr_info("maria: Packet tap hook registered successfully via dev_add_pack.\n");

    return 0;
}

static void __exit maria_exit(void)
{
    pr_info("maria: Cleaning up module...\n");

    dev_remove_pack(&maria_packet_type);

    if (maria_nl_sock) {
        netlink_kernel_release(maria_nl_sock);
        maria_nl_sock = NULL;
    }

    atomic_set(&user_pid, 0);
    pr_info("maria: Module unloaded successfully.\n");
}

module_init(maria_init);
module_exit(maria_exit);
