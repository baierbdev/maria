#ifndef _MARIA_PACKET_PROTOCOL_H_
#define _MARIA_PACKET_PROTOCOL_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/if.h>
#else
#include <stdint.h>
#include <net/if.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

#define MARIA_NL_UNIT        2     /* NETLINK_USERSOCK (unit 2) */
#define MARIA_MAX_PAYLOAD    1024  /* Capture up to 1KB of payload per packet */

/* Message types for Netlink communication */
enum maria_msg_type {
    MARIA_MSG_REGISTER   = 1, /* Userspace -> Kernel: Register daemon PID */
    MARIA_MSG_UNREGISTER = 2, /* Userspace -> Kernel: Unregister daemon PID */
    MARIA_MSG_HEARTBEAT  = 3, /* Keepalive / Ping */
    MARIA_MSG_PACKET     = 4, /* Kernel -> Userspace: Packet event */
    MARIA_MSG_ACK        = 5, /* Kernel -> Userspace: Status acknowledgement */
};

/* TCP flag bitmasks */
#define MARIA_TCP_FIN 0x01
#define MARIA_TCP_SYN 0x02
#define MARIA_TCP_RST 0x04
#define MARIA_TCP_PSH 0x08
#define MARIA_TCP_ACK 0x10
#define MARIA_TCP_URG 0x20

/* Captured packet metadata and payload */
struct maria_packet_data {
    __u64 timestamp_ns;               /* Nanosecond timestamp */
    __u32 src_ip;                     /* IPv4 source address (network byte order) */
    __u32 dst_ip;                     /* IPv4 destination address (network byte order) */
    __u16 src_port;                   /* Source port (host byte order) */
    __u16 dst_port;                   /* Destination port (host byte order) */
    __u16 payload_len;                /* Payload length copied to payload[] */
    __u16 total_len;                  /* Total IP packet length */
    __u8  protocol;                   /* IPPROTO_TCP (6), IPPROTO_UDP (17), IPPROTO_ICMP (1) */
    __u8  tcp_flags;                  /* TCP flags if TCP */
    char  ifname[IFNAMSIZ];           /* Network interface name (e.g., eth0) */
    __u8  payload[MARIA_MAX_PAYLOAD]; /* Packet payload bytes */
} __attribute__((packed));

/* Envelope for Netlink messages */
struct maria_nl_msg {
    __u32 type;                       /* enum maria_msg_type */
    __u32 len;                        /* Length of payload */
    union {
        struct maria_packet_data pkt;
        char status_msg[64];
    } data;
} __attribute__((packed));

#endif /* _MARIA_PACKET_PROTOCOL_H_ */
