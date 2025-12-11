
//
// Copyright (c) 2025, Denny Page
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#ifndef _PROTOCOLS_H
#define _PROTOCOLS_H 1

#include <stdint.h>


//
// Not all types and structures are consistantly available or have consistent
// naming on various systems, so for simplicity we define our own here.
//


// Ethernet address (array of uint8_t)
#define MCB_ETH_ADDR_LEN            6
#define MCB_ETH_ADDR_CMP(ca1, ca2)  memcmp((ca1), (ca2), MCB_ETH_ADDR_LEN)
#define MCB_ETH_ADDR_CPY(dst, src)  memcpy((dst), (src), MCB_ETH_ADDR_LEN)

// Ethernet Types
#define MCB_ETHERNET_TYPE_IP4       0x0800
#define MCB_ETHERNET_TYPE_IP6       0x86dd


// IPv4 address length in uint8_t
#define MCB_IP4_ADDR_LEN            4
#define MCB_IP4_ADDR_CMP(ca1, ca2)  memcmp((ca1), (ca2), MCB_IP4_ADDR_LEN)
#define MCB_IP4_ADDR_CPY(dst, src)  memcpy((dst), (src), MCB_IP4_ADDR_LEN)
#define MCB_IP4_ADDR_SET(dst, val)  memset((dst), (val), MCB_IP4_ADDR_LEN)

// IPv4 addresses
#define MCB_IP4_ANY                 { 0x00, 0x00, 0x00, 0x00 }
#define MCB_IP4_ALL_SYSTEMS         0xe0000001
#define MCB_IP4_ALL_ROUTERS         0xe0000002
#define MCB_IP4_ALL_REPORTS         0xe0000016
#define MCB_IP4_ALL_SNOOPERS        0xe000006a

// IPv4 Types
#define MCB_IP4_PROTOCOL_IGMP       2
#define MCB_IP4_OFF_DF              0x4000
#define MCB_IP4_OPT_RA              0x94
#define MCB_IP4_TOS_IC              0xc0

// IGMP Types
#define MCB_IGMP_QUERY              0x11    // General query (group address zero) sent to all systems group
                                            // Group specific query sent to the multicast group in question (v2/v3 only)
#define MCB_IGMP_V1_REPORT          0x12    // Sent to the multicast group in question (v1 only)
#define MCB_IGMP_V2_REPORT          0x16    // Sent to the multicast group in question (v2 only)
#define MCB_IGMP_V2_LEAVE           0x17    // Sent to all routers group (v2 only)
#define MCB_IGMP_V3_REPORT          0x22    // Sent to the all reports group (v3 only)
#define MCB_IGMP_MRD_ADVERTISEMENT  0x30    // Sent to the all snoopers group
#define MCB_IGMP_MRD_SOLICITATION   0x31    // Sent to the all routers group
#define MCB_IGMP_MRD_TERMINATION    0x32    // Sent to the all snoopers group

// IGMP protocol parameters (defaults from RFC 2236 & RFC 9776)
#define MCB_IGMP_ROBUSTNESS         2
#define MCB_IGMP_QUERY_INTERVAL     125     // seconds
#define MCB_IGMP_RESPONSE_INTERVAL  100     // 10ths of a second
#define MCB_IGMP_LASTMBR_INTERVAL   10      // 10ths of a second


// IPv6 address length in uint8_t
#define MCB_IP6_ADDR_LEN            16
#define MCB_IP6_ADDR_CMP(ca1, ca2)  memcmp((ca1), (ca2), MCB_IP6_ADDR_LEN)
#define MCB_IP6_ADDR_CPY(dst, src)  memcpy((dst), (src), MCB_IP6_ADDR_LEN)
#define MCB_IP6_ADDR_SET(dst, val)  memset((dst), (val), MCB_IP6_ADDR_LEN)

// IPv6 Addresses
#define MCB_IP6_ANY                 { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MCB_IP6_ALL_NODES           { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
#define MCB_IP6_ALL_ROUTERS         { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }
#define MCB_IP6_ALL_ROUTERS_V2      { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 }
#define MCB_IP6_ALL_SNOOPERS        { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a }

// IPv6 Types
#define MCB_IP6_OPT_PADN            0x01
#define MCB_IP6_OPT_HOP             0x00
#define MCB_IP6_OPT_RA              0x05
#define MCB_IP6_PROTO_ICMPV6        0x3a

// MLD Types
#define MCB_MLD_QUERY               0x82    // General query (group address zero) sent to all systems group
                                            // Group specific query sent to the multicast group in question
#define MCB_MLD_V1_REPORT           0x81    // Sent to the multicast group in question
#define MCB_MLD_V1_DONE             0x83    // Sent to all routers group
#define MCB_MLD_V2_REPORT           0x8f    // Sent to all routers v2 group
#define MCB_MLD_MRD_ADVERTISEMENT   0x97    // Sent to the all snoopers group
#define MCB_MLD_MRD_SOLICITATION    0x98    // Sent to the all routers group
#define MCB_MLD_MRD_TERMINATION     0x99    // Sent to the all snoopers group

// MLD protocol parameters (defaults from RFC 2710 & RFC 9777)
#define MCB_MLD_ROBUSTNESS          2
#define MCB_MLD_QUERY_INTERVAL      125     // seconds
#define MCB_MLD_RESPONSE_INTERVAL   10000   // milliseconds
#define MCB_MLD_LASTMBR_INTERVAL    1000    // milliseconds


// Common Record Types for both IGMPv3 and MLDv2
#define MCB_REC_MODE_IS_INCLUDE     0x01
#define MCB_REC_MODE_IS_EXCLUDE     0x02
#define MCB_REC_CHANGE_TO_INCLUDE   0x03
#define MCB_REC_CHANGE_TO_EXCLUDE   0x04
#define MCB_REC_ALLOW_NEW_SOURCES   0x05
#define MCB_REC_BLOCK_OLD_SOURCES   0x06


// MRD protocol parameters for both IGMP and MLD (defaults from RFC 4286)
#define MCB_MRD_INTERVAL            20    // seconds
#define MCB_MRD_INTERVAL_JITTER     500   // milliseconds (advertisement interval * 0.25)
#define MCB_MRD_INITIAL_INTERVAL    2     // seconds
#define MCB_MRD_INITIAL_COUNT       3

// Number of milliseconds until the next MRD advertisement
#define MCB_MRD_INTERVAL_MS         \
    (((MCB_MRD_INTERVAL * 1000) - MCB_MRD_INTERVAL_JITTER) + \
     (rand() % (MCB_MRD_INTERVAL_JITTER * 2)))

// Number of milliseconds until the next initial (startup) MRD advertisement
#define MCB_MRD_INITIAL_INTERVAL_MS \
    (rand() % ((MCB_MRD_INITIAL_INTERVAL * 1000)))


// Ethernet header structure
typedef struct __attribute__((packed))
{
    uint8_t                     dst[MCB_ETH_ADDR_LEN];
    uint8_t                     src[MCB_ETH_ADDR_LEN];
    uint16_t                    type;
} mcb_ethernet_t;



// IP header structure
typedef struct __attribute__((packed))
{
#if BYTE_ORDER == BIG_ENDIAN
    // IP version (4)
    uint8_t                     version:4,
    // Size of IP header in 32-bit words
                                header_len:4;
#elif BYTE_ORDER == LITTLE_ENDIAN
    // Size of IP header in 32-bit words
    uint8_t                     header_len:4,
    // IP version (4)
                                version:4;
#else
#error "Unknown byte order"
#endif
    // Type of service
    uint8_t                     tos;
    // Total length of IP packet
    uint16_t                    total_len;
    // Identification
    uint16_t                    id;
    // Flags and fragment offset
    uint16_t                    offset;
    // Time to live
    uint8_t                     ttl;
    // Protocol
    uint8_t                     protocol;
    // IP header checksum (includes options)
    uint16_t                    csum;
    // Source and destination addresses
    uint8_t                     src[MCB_IP4_ADDR_LEN];
    uint8_t                     dst[MCB_IP4_ADDR_LEN];
} mcb_ip4_t;

// IPv4 Router Alert structure
typedef struct __attribute__((packed))
{
    // Type is 0x94 (0x80 Copy on fragmentation flag + 0x14 Router Alert)
    uint8_t                     type;
    // Length is 4
    uint8_t                     length;
    // Value is 0
    uint16_t                    value;
} mcb_ip4_ra_opt_t;

// IGMP v1/v2/3 common header structure
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Max Response Time in tenths of a second
    uint8_t                     code;
    // Checksum
    uint16_t                    csum;
    // Group Address (not present in v3 reports)
    uint8_t                     group[MCB_IP4_ADDR_LEN];
} mcb_igmp_t;

// IGMP v3 Group Record structure
typedef struct __attribute__((packed))
{
    // Record Type
    uint8_t                     type;
    // Aux Data Len (in 32-bit words)
    uint8_t                     aux_len;
    // Number of Sources
    uint16_t                    num_srcs;
    // Group Address
    uint8_t                     group[MCB_IP4_ADDR_LEN];
    // Source Addresses
    uint8_t                     srcs[][MCB_IP4_ADDR_LEN];
} mcb_igmp_v3_group_record_t;

// IGMP v3 Membership Query structure
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Max Response Code in tenths of a second
    //   If the code is < 128, it directly represents the value
    //   If the code is >= 128, it represents a floating-point encoded like so:
    //      0 1 2 3 4 5 6 7
    //     +-+-+-+-+-+-+-+-+
    //     |1| exp | mant  |
    //     +-+-+-+-+-+-+-+-+
    //   and the value is (mant | 0x10) << (exp + 3)
    uint8_t                     code;
    // Checksum
    uint16_t                    csum;
    // Group Address
    uint8_t                     group[MCB_IP4_ADDR_LEN];
#if BYTE_ORDER == BIG_ENDIAN
    // Reserved flags (0)
    uint8_t                     reserved_flags:4,
    // S flag (Suppress Router-Side Processing)
                                s_flag:1,
    // Querier Robustness Value
                                qrv:3;
#elif BYTE_ORDER == LITTLE_ENDIAN
    // Querier Robustness Value
    uint8_t                     qrv:3,
    // S flag (Suppress Router-Side Processing)
                                s_flag:1,
    // Reserved flags (0)
                                reserved_flags:4;
#else
#error "Unknown byte order"
#endif
    // QQIC (Querier's Query Interval Code) in seconds
    //   If the code is < 128, it directly represents the value
    //   If the code is >= 128, it represents a floating-point encoded like so:
    //      0 1 2 3 4 5 6 7
    //     +-+-+-+-+-+-+-+-+
    //     |1| exp | mant  |
    //     +-+-+-+-+-+-+-+-+
    //   and the value is (mant | 0x10) << (exp + 3)
    uint8_t                     qqic;
    // Number of Sources
    uint16_t                    num_srcs;
    // Source Addresses
    uint8_t                     srcs[][MCB_IP4_ADDR_LEN];
} mcb_igmp_v3_query_t;

// IGMP v3 Membership Report structure
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Reserved (0)
    uint8_t                     reserved;
    // Checksum
    uint16_t                    csum;
    // Flags
    uint16_t                    flags;
    // Number of Group Records
    uint16_t                    num_groups;
    // Group Records
    mcb_igmp_v3_group_record_t  groups[];
} mcb_igmp_v3_report_t;


// IPv6 header structure
typedef struct __attribute__((packed))
{
    // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint32_t                    v_tc_flow;
    // Payload Length
    uint16_t                    payload_len;
    // Next Header
    uint8_t                     next_header;
    // Hop Limit
    uint8_t                     hop_limit;
    // Source and destination addresses
    uint8_t                     src[MCB_IP6_ADDR_LEN];
    uint8_t                     dst[MCB_IP6_ADDR_LEN];
} mcb_ip6_t;

// IPv6 hop-by-hop structure
typedef struct __attribute__((packed))
{
    // Next Header
    uint8_t                     next_header;
    // Header Extension Length
    uint8_t                     header_len;
    // Options and padding (variable length ending on 8 byte boundary, 6 byte minimum)
    uint8_t                     options[6];
} mcb_ip6_hbh_t;

// IPv6 PadN option structure (inside hop by hop)
typedef struct __attribute__((packed))
{
    // Option (1)
    uint8_t                     option;
    // Length
    uint8_t                     length;
} mcb_ip6_padn_t;

// IPv6 Router Alert option structure (inside hop by hop)
typedef struct __attribute__((packed))
{
    // Option (5)
    uint8_t                     option;
    // Length (2)
    uint8_t                     length;
    // Value
    uint16_t                    value;
} mcb_ip6_ra_t;

// MLD v1 structure
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Code (0)
    uint8_t                     code;
    // Checksum
    uint16_t                    csum;
    // Maximum Response Delay in milliseconds
    uint16_t                    response;
    // Reserved (0)
    uint16_t                    reserved;
    // Multicast Address
    uint8_t                     group[MCB_IP6_ADDR_LEN];
} mcb_mld_t;

// MLD v2 Address record structure
typedef struct __attribute__((packed))
{
    // Record Type
    uint8_t                     type;
    // Aux Data Len (in 32-bit words)
    uint8_t                     aux_len;
    // Number of Sources
    uint16_t                    num_srcs;
    // Group Address
    uint8_t                     group[MCB_IP6_ADDR_LEN];
    // Source Addresses
    uint8_t                     srcs[][MCB_IP6_ADDR_LEN];
} mcb_mld_v2_group_record_t;

// MLD v2 query structure
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Code (0)
    uint8_t                     code;
    // Checksum
    uint16_t                    csum;
    // Maximum Response Code in milliseconds
    //   If the code is < 32768, it directly represents the value
    //   If the code is >= 32768, it represents a floating-point encoded like so:
    //      0 1 2 3 4 5 6 7 8 9 A B C D E F
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |1| exp |          mant         |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   and the value is (mant | 0x1000) << (exp + 3)
    uint16_t                    response;
    // Reserved (0)
    uint16_t                    reserved;
    // Multicast Address
    uint8_t                     group[MCB_IP6_ADDR_LEN];
#if BYTE_ORDER == BIG_ENDIAN
    // Reserved flags (0)
    uint8_t                     reserved_flags:4,
    // S flag (Suppress Router-Side Processing)
                                s_flag:1,
    // Querier Robustness Value
                                qrv:3;
#elif BYTE_ORDER == LITTLE_ENDIAN
    // Querier Robustness Value
    uint8_t                     qrv:3,
    // S flag (Suppress Router-Side Processing)
                                s_flag:1,
    // Reserved flags (0)
                                reserved_flags:4;
#else
#error "Unknown byte order"
#endif
    // QQIC (Querier's Query Interval Code) in seconds
    //   If the code is < 128, it directly represents the value
    //   If the code is >= 128, it represents a floating-point encoded like so:
    //      0 1 2 3 4 5 6 7
    //     +-+-+-+-+-+-+-+-+
    //     |1| exp | mant  |
    //     +-+-+-+-+-+-+-+-+
    //   and the value is (mant | 0x10) << (exp + 3)
    uint8_t                     qqic;
    // Number of Sources
    uint16_t                    num_srcs;
    // Source Addresses
    uint8_t                     srcs[][MCB_IP6_ADDR_LEN];
} mcb_mld_v2_query_t;

// MLD v2 Multicast Listener Report structure
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Reserved (0)
    uint8_t                     reserved1;
    // Checksum
    uint16_t                    csum;
    // Flags (0)
    uint16_t                    flags;
    // Number of Address Records
    uint16_t                    num_groups;
    // Address Records
    mcb_mld_v2_group_record_t   groups[];
} mcb_mld_v2_report_t;


// Multicast Router Advertisement structure (common to IGMP and MLD)
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Advertisement Interval in seconds
    uint8_t                     interval;
    // Checksum
    uint16_t                    csum;
    // Querier Query Interval in seconds
    uint16_t                    qqi;
    // Querier Robustness Value
    uint16_t                    qrv;
}
mcb_mrd_advertisement_t;

// Multicast Router Solicitation structure (common to both IGMP and MLD)
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Advertisement Interval in seconds
    uint8_t                     reserved;
    // Checksum
    uint16_t                    csum;
}
mcb_mrd_solicitation_t;

// Multicast Router Termination structure (common to both IGMP and MLD)
typedef struct __attribute__((packed))
{
    // Type
    uint8_t                     type;
    // Advertisement Interval in seconds
    uint8_t                     reserved;
    // Checksum
    uint16_t                    csum;
}
mcb_mrd_termination_t;

#endif // _PROTOCOLS_H
