
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


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "common.h"
#include "protocols.h"


//
// The MLD implementation herein is primarily based on RFC 2236 and RFC 9976.
//
// The implementation deviates from the standards in the following aspects:
//
//  1. The implementation ignores all link-local scope multicast addresses (ff02::/16).
//
//  2. The MLDv2 implementation works at the IP group level only, ignoring all source
//     specific address information. This is similar to some switches or routers with
//     the forwarding method set to "IP Group Address" instead of "Source Specific IP
//     Group Address".
//
//  3. The implementation offers multiple querier modes:
//     * Never - The querier function is disabled.
//     * Quick - Become a querier immediately at startup (corresponds to RFC behavior).
//     * Delay - Become a querier after 125 seconds if no other querier has been seen.
//     * Defer - Become a querier after 125 seconds if no other querier has been seen,
//               and always defer to any other queriers that may appear regardless of
//               relative IP address.
//
//  4. The implementation allows a few milliseconds of grace time for protocol timeouts
//     to allow for network round trip and host processing time.
//
//
//
// The Multicast Router Discovery implementation is based on RFC 4286.
//
// Minor notes regarding the implementation:
//
//  1. The implementation does not wait a random interval prior to sending the first
//     Multicast Router Discovery Advertisement message, however subequent initial
//     advertisements are sent with a random interval.
//  2. No Multiast Router Discovery Termination messages are sent.
//



// Pcap MLD filter
//
//   Expected Packet format:
//     Ethernet header
//     IPv6 header with next header as Hop-by-Hop
//     Hop-by-Hop header with embedded Router Alert and next header as ICMPv6
//     ICMPv6/MLD header
//
//   Filter notes:
//     Offset 40 is the next header type in the Hop-by-Hop header
//     Header type 58 is ICMPv6
//     Offset 48 is the ICMPv6 (MLD) message type
//
#define MLD_FILTER              "ip6 && ip6[40] == 58 && (ip6[48] == 130 || ip6[48] == 131 || ip6[48] == 132 || ip6[48] == 143 || ip6[48] == 152)"

// Buffer sizes
#define MLD_MRD_BUFFER_SIZE     (sizeof(mcb_ethernet_t) +sizeof(mcb_ip6_t) + sizeof(mcb_ip6_hbh_t) + sizeof(mcb_mrd_advertisement_t))
#define MLD_QUERY_BUFFER_SIZE   (sizeof(mcb_ethernet_t) +sizeof(mcb_ip6_t) + sizeof(mcb_ip6_hbh_t) + sizeof(mcb_mld_v2_query_t))

// Grace period for protocol timeouts in milliseconds
#define GRACE_MILLIS            10


// MLD group structure
typedef struct mld_interface    mld_interface_t;
typedef struct mld_group
{
    // The mld interface this group belongs to
    mld_interface_t *           mld_interface;

    // Bridge interface list
    bridge_interface_t **       bridge_interface_list;
    unsigned int                bridge_interface_list_allocated;
    unsigned int                bridge_interface_list_count;

    // Is the group currently active?
    unsigned int                active;

    // Group address
    uint8_t                     mcast_addr[MCB_IP6_ADDR_LEN];

    // MLD parameters
    unsigned int                group_queries_remaining;
} mld_group_t;

// MLD interface structure
typedef struct mld_interface
{
    // MLD groups
    mld_group_t *               group_list;
    unsigned int                group_list_allocated;
    unsigned int                group_list_count;
    unsigned int                group_list_fixed_limit;

    // Interface name, index and address
    char *                      name;
    unsigned int                if_index;
    uint8_t                     if_addr[MCB_IP6_ADDR_LEN];
    uint8_t                     if_mac_addr[MCB_ETH_ADDR_LEN];

    // Pcap handle
    pcap_t *                    pcap;

    // Current MLD querier variables
    uint8_t                     querier_addr[MCB_IP6_ADDR_LEN];
    unsigned int                querier_robustness;
    unsigned int                querier_interval_sec;
    unsigned int                querier_response_interval_millis;
    unsigned int                querier_lastmbr_interval_millis;

    // Number of initial multicast router advertisements remaining
    unsigned int                mrd_initial_advertisements_remaining;

    // Number of startup queries remaining
    unsigned int                startup_queries_remaining;

    // Packet for multicast router advertisements
    uint8_t                     mrd_advertisement_packet[MLD_MRD_BUFFER_SIZE];

    // Packets for general and group specific queries
    uint8_t                     general_query_packet[MLD_QUERY_BUFFER_SIZE];
    uint8_t                     specific_query_packet[MLD_QUERY_BUFFER_SIZE];
} mld_interface_t;


// MLD event manager
static evm_t *                  mld_evm;

// MLD interface list
static mld_interface_t *        mld_interface_list = NULL;
static unsigned int             mld_interface_list_allocated = 0;
static unsigned int             mld_interface_list_count = 0;

// Special addresses
static uint8_t                  any_addr[MCB_IP6_ADDR_LEN] = MCB_IP6_ANY;
static uint8_t                  allnodes_addr[MCB_IP6_ADDR_LEN] = MCB_IP6_ALL_NODES;
static uint8_t                  allsnoopers_addr[MCB_IP6_ADDR_LEN] = MCB_IP6_ALL_SNOOPERS;



//
// Log an MLD issue
//
static void mld_log(
    const mld_interface_t *     mld_interface,
    const uint8_t *             addr,
    const char *                msg)
{
    char                        addr_str[INET6_ADDRSTRLEN] = {0};

    // Minimum debug log level
    if (debug_level < 2)
    {
        return;
    }

    // Format the address
    if (addr)
    {
        inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
    }

    logger("MLD(%s) [%s]: %s\n", mld_interface->name, addr_str, msg);
}


//
// Build the multicast router advertisement packet
//
static void mld_build_mrd_advertisement_packet(
    mld_interface_t *           mld_interface)
{
    mcb_ethernet_t *            ethernet;
    mcb_ip6_t *                 ip;
    mcb_ip6_hbh_t *             ip_hbh;
    mcb_ip6_padn_t *            ip_padn;
    mcb_ip6_ra_t *              ip_ra;
    mcb_mrd_advertisement_t *   mrd_advertisement;
    uint8_t                     buffer[MLD_MRD_BUFFER_SIZE];

    // Initialize the buffer
    memset(buffer, 0, sizeof(buffer));

    // Pointers to the individual headers
    ethernet = (mcb_ethernet_t *) buffer;
    ip = (mcb_ip6_t *) (buffer + sizeof(mcb_ethernet_t));
    ip_hbh = (mcb_ip6_hbh_t *) (buffer + sizeof(mcb_ethernet_t) + sizeof(mcb_ip6_t));
    ip_ra = (mcb_ip6_ra_t *) &ip_hbh->options[0];
    ip_padn = (mcb_ip6_padn_t *) &ip_hbh->options[4];
    mrd_advertisement = (mcb_mrd_advertisement_t *) (buffer + sizeof(mcb_ethernet_t) + sizeof(mcb_ip6_t) + sizeof(mcb_ip6_hbh_t));

    // Build the Ethernet header
    ethernet->type = htons(MCB_ETHERNET_TYPE_IP6);
    // NB: The format of the dst addr for IPv6 multicast is 33:33:XX:XX:XX:XX where
    // XX:XX:XX:XX is the last 4 bytes of the IPv6 multicast address.
    ethernet->dst[0] = 0x33;
    ethernet->dst[1] = 0x33;
    memcpy(&ethernet->dst[2], &allsnoopers_addr[12], 4);
    MCB_ETH_ADDR_CPY(ethernet->src, mld_interface->if_mac_addr);

    // Build the IP header
    ip->v_tc_flow = htonl(0x60000000);
    ip->payload_len = htons(sizeof(mcb_ip6_hbh_t) + sizeof(mcb_mrd_advertisement_t));
    ip->next_header = MCB_IP6_OPT_HOP;
    ip->hop_limit = 1;
    MCB_IP6_ADDR_CPY(ip->src, mld_interface->if_addr);
    MCB_IP6_ADDR_CPY(ip->dst, allsnoopers_addr);

    // Build the Hop-by-Hop header
    ip_hbh->next_header = MCB_IP6_PROTO_ICMPV6;
    // ip_hbh->header_len is zero
    ip_ra->option = MCB_IP6_OPT_RA;
    ip_ra->length = 2;
    // ip_ra->value is zero (MLD)
    ip_padn->option = MCB_IP6_OPT_PADN;
    // ip_padn->length is zero

    // Build the MRD Advertisement
    mrd_advertisement->type = MCB_MLD_MRD_ADVERTISEMENT;
    mrd_advertisement->interval = MCB_MRD_INTERVAL;
    mrd_advertisement->qqi = htons(MCB_MLD_QUERY_INTERVAL);
    mrd_advertisement->qrv = htons(MCB_MLD_ROBUSTNESS);

    // Set the checksum
    mrd_advertisement->csum = inet6_csum((uint16_t *) mrd_advertisement, sizeof(*mrd_advertisement),
        (uint16_t *) ip->src, (uint16_t *) ip->dst, MCB_IP6_PROTO_ICMPV6);
    memcpy(mld_interface->mrd_advertisement_packet, buffer, sizeof(mld_interface->mrd_advertisement_packet));
}


//
// Build the general and group specific query packets for an interface
//
static void mld_build_query_packets(
    mld_interface_t *           mld_interface)
{
    mcb_ethernet_t *            ethernet;
    mcb_ip6_t *                 ip;
    mcb_ip6_hbh_t *             ip_hbh;
    mcb_ip6_padn_t *            ip_padn;
    mcb_ip6_ra_t *              ip_ra;
    mcb_mld_v2_query_t *        mld_query;
    uint8_t                     buffer[MLD_QUERY_BUFFER_SIZE];

    // Initialize the buffer
    memset(buffer, 0, sizeof(buffer));

    // Pointers to the individual headers
    ethernet = (mcb_ethernet_t *) buffer;
    ip = (mcb_ip6_t *) (buffer + sizeof(mcb_ethernet_t));
    ip_hbh = (mcb_ip6_hbh_t *) (buffer + sizeof(mcb_ethernet_t) + sizeof(mcb_ip6_t));
    ip_ra = (mcb_ip6_ra_t *) &ip_hbh->options[0];
    ip_padn = (mcb_ip6_padn_t *) &ip_hbh->options[4];
    mld_query = (mcb_mld_v2_query_t *) (buffer + sizeof(mcb_ethernet_t) + sizeof(mcb_ip6_t) + sizeof(mcb_ip6_hbh_t));

    // Build the Ethernet header
    ethernet->type = htons(MCB_ETHERNET_TYPE_IP6);
    // NB: The format of the dst addr for IPv6 multicast is 33:33:XX:XX:XX:XX where
    // XX:XX:XX:XX is the last 4 bytes of the IPv6 multicast address. The bottom 4 bytes
    // of the address and will be filled in later.
    ethernet->dst[0] = 0x33;
    ethernet->dst[1] = 0x33;
    MCB_ETH_ADDR_CPY(ethernet->src, mld_interface->if_mac_addr);

    // Build the IP header
    ip->v_tc_flow = htonl(0x60000000);
    ip->payload_len = htons(sizeof(mcb_ip6_hbh_t) + sizeof(mcb_mld_v2_query_t));
    ip->next_header = MCB_IP6_OPT_HOP;
    ip->hop_limit = 1;
    MCB_IP6_ADDR_CPY(ip->src, mld_interface->if_addr);

    // Build the Hop-by-Hop header
    ip_hbh->next_header = MCB_IP6_PROTO_ICMPV6;
    // ip_hbh->header_len is zero
    ip_ra->option = MCB_IP6_OPT_RA;
    ip_ra->length = 2;
    // ip_ra->value is zero (MLD)
    ip_padn->option = MCB_IP6_OPT_PADN;
    // ip_padn->length is zero

    // Build the MLD v2 query header
    mld_query->type = MCB_MLD_QUERY;
    mld_query->qrv = MCB_MLD_ROBUSTNESS;
    mld_query->qqic = MCB_MLD_QUERY_INTERVAL;

    // Set up the group specific query packet
    // NB: ethernet->dst, ip->dst, mld->csum and mld->mld_group are finalized in send_group_specific_query()
    mld_query->response = htons(MCB_MLD_LASTMBR_INTERVAL);
    memcpy(mld_interface->specific_query_packet, buffer, sizeof(mld_interface->specific_query_packet));

    // Set up the general query packet
    memcpy(&ethernet->dst[2], &allnodes_addr[12], 4);
    MCB_IP6_ADDR_CPY(ip->dst, allnodes_addr);
    mld_query->response = htons(MCB_MLD_RESPONSE_INTERVAL);
    mld_query->csum = inet6_csum((uint16_t *) mld_query, sizeof(*mld_query),
        (uint16_t *) ip->src, (uint16_t *) ip->dst, MCB_IP6_PROTO_ICMPV6);
    memcpy(mld_interface->general_query_packet, buffer, sizeof(mld_interface->general_query_packet));
}


//
// Send a multicast router advertisement
//
static void mld_send_mrd_advertisement(
    void *                      arg)
{
    mld_interface_t *           mld_interface = (mld_interface_t *) arg;
    unsigned int                millis;
    int                         r;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, mld_interface->if_addr, src_addr_str, sizeof(src_addr_str));
        logger("MLD(%s) [%s]: sending Multicast Router Discovery advertisement\n", mld_interface->name, src_addr_str);
    }

    r = pcap_inject(mld_interface->pcap, mld_interface->mrd_advertisement_packet, sizeof(mld_interface->mrd_advertisement_packet));
    if (r == PCAP_ERROR)
    {
        logger("MLD(%s): pcap_inject failed: %s\n", mld_interface->name, pcap_geterr(mld_interface->pcap));
    }

    // Set the next advertisement interval
    if (mld_interface->mrd_initial_advertisements_remaining)
    {
        // Are we in startup mode?
        mld_interface->mrd_initial_advertisements_remaining -= 1;
        millis = MCB_MRD_INITIAL_INTERVAL_MS;
    }
    else
    {
        millis = MCB_MRD_INTERVAL_MS;
    }

    // Set a timer for the next advertisement
    evm_add_timer(mld_evm, millis, mld_send_mrd_advertisement, mld_interface);
}


//
// Send a general query
//
static void mld_send_general_query(
    void *                      arg)
{
    mld_interface_t *           mld_interface = (mld_interface_t *) arg;
    unsigned int                millis;
    int                         r;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, mld_interface->if_addr, src_addr_str, sizeof(src_addr_str));
        logger("MLD(%s) [%s]: sending general query\n", mld_interface->name, src_addr_str);
    }

    // Send the query
    r = pcap_inject(mld_interface->pcap, mld_interface->general_query_packet, sizeof(mld_interface->general_query_packet));
    if (r == PCAP_ERROR)
    {
        logger("MLD(%s): pcap_inject failed: %s\n", mld_interface->name, pcap_geterr(mld_interface->pcap));
    }

    // Set the next query interval
    millis = mld_interface->querier_interval_sec * 1000;
    if (mld_interface->startup_queries_remaining)
    {
        // Are we in startup mode?
        mld_interface->startup_queries_remaining -= 1;
        millis /= 4;
    }

    // Set a timer for the next query
    evm_add_timer(mld_evm, millis, mld_send_general_query, mld_interface);
}


//
// Send a group specific query
//
static void send_group_specific_query(
    void *                      arg)
{
    mld_group_t *               mld_group = (mld_group_t *) arg;
    mld_interface_t *           mld_interface = mld_group->mld_interface;
    uint8_t *                   mcast_addr = mld_group->mcast_addr;
    mcb_ethernet_t *            ethernet;
    mcb_ip6_t *                 ip;
    mcb_mld_v2_query_t *        mld_query;
    int                         r;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET6_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, mld_interface->if_addr, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET6, mcast_addr, group_addr_str, sizeof(group_addr_str));
        logger("MLD(%s) [%s]: sending query [group %s]\n", mld_interface->name, src_addr_str, group_addr_str);
    }

    // Pointers to the individual headers
    ethernet = (mcb_ethernet_t *) mld_interface->specific_query_packet;
    ip = (mcb_ip6_t *) (mld_interface->specific_query_packet + sizeof(mcb_ethernet_t));
    mld_query = (mcb_mld_v2_query_t *) (mld_interface->specific_query_packet + sizeof(mcb_ethernet_t) + sizeof(mcb_ip6_t) + sizeof(mcb_ip6_hbh_t));

    // Set the remaining 4 bytes of the ethernet destination address
    memcpy(&ethernet->dst[2], &mcast_addr[12], 4);

    // Set the ip destination and mld group
    MCB_IP6_ADDR_CPY(ip->dst, mcast_addr);
    MCB_IP6_ADDR_CPY(mld_query->group, mcast_addr);

    // Set the S flag as appropriate
    if (mld_group->group_queries_remaining ==  mld_interface->querier_robustness)
    {
        mld_query->s_flag = 0;
    }
    else
    {
        mld_query->s_flag = 1;
    }

    // Calculate the MLD checksum
    mld_query->csum = 0;
    mld_query->csum = inet6_csum((uint16_t *) mld_query, sizeof(*mld_query),
        (uint16_t *) ip->src, (uint16_t *) ip->dst, MCB_IP6_PROTO_ICMPV6);

    // Send the query
    r = pcap_inject(mld_interface->pcap, mld_interface->specific_query_packet, sizeof(mld_interface->specific_query_packet));
    if (r == PCAP_ERROR)
    {
        logger("MLD(%s): pcap_inject failed: %s\n", mld_interface->name, pcap_geterr(mld_interface->pcap));
    }

    // Do we need to send more?
    mld_group->group_queries_remaining -= 1;
    if (mld_group->group_queries_remaining)
    {
        evm_add_timer(mld_evm, mld_interface->querier_lastmbr_interval_millis, send_group_specific_query, mld_group);
        return;
    }
}


//
// Activate querier mode
//
static void mld_activate_querier_mode(
    mld_interface_t *           mld_interface)
{
    mld_log(mld_interface, mld_interface->if_addr, "Querier mode activated");

    // Set the querier parameters
    mld_interface->querier_robustness = MCB_MLD_ROBUSTNESS;
    mld_interface->querier_interval_sec = MCB_MLD_QUERY_INTERVAL;
    mld_interface->querier_response_interval_millis = MCB_MLD_RESPONSE_INTERVAL;
    mld_interface->querier_lastmbr_interval_millis = MCB_MLD_LASTMBR_INTERVAL;

    // Set my address as the querier
    MCB_IP6_ADDR_CPY(mld_interface->querier_addr, mld_interface->if_addr);

    // Send the first general query
    mld_interface->startup_queries_remaining = mld_interface->querier_robustness - 1;
    mld_send_general_query(mld_interface);
}


//
// MLD querier timeout
//
static void mld_querier_timeout(
    void *                      arg)
{
    mld_interface_t *           mld_interface = (mld_interface_t *) arg;

    mld_log(mld_interface, mld_interface->querier_addr, "Querier timeout");

    if (mld_querier_mode)
    {
        // Activate as the querier
        mld_activate_querier_mode(mld_interface);
    }
    else
    {
        mld_log(mld_interface, mld_interface->if_addr, "Querier mode disabled");

        // Reset the querier address to all ones
        MCB_IP6_ADDR_SET(mld_interface->querier_addr, 0xff);
    }
}


//
// MLD group timeout
//
static void mld_group_timeout(
    void *                      arg)
{
    mld_group_t *               mld_group = arg;
    mld_interface_t *           mld_interface = mld_group->mld_interface;
    unsigned int                group_index;
    unsigned int                bridge_interface_index;

    mld_log(mld_interface, mld_group->mcast_addr, "Group membership timeout");

    // Mark the group as inactive
    mld_group->active = 0;

    // Is this one of the registered groups?
    if (mld_group->bridge_interface_list_count)
    {
        // deactivate the outbound interfaces
        for (bridge_interface_index = 0; bridge_interface_index < mld_group->bridge_interface_list_count; bridge_interface_index += 1)
        {
            interface_deactivate_outbound(mld_group->bridge_interface_list[bridge_interface_index]);
        }
        return;
    }

    // Tighten up the group list count if possible
    for (group_index = mld_interface->group_list_count - 1; group_index > mld_interface->group_list_fixed_limit; group_index -= 1)
    {
        if (mld_interface->group_list[group_index].active)
        {
            break;
        }
        mld_interface->group_list_count -= 1;
    }
}


//
// Find a group in the group list for an interface
//
static mld_group_t * mld_interface_find_group(
    mld_interface_t *           mld_interface,
    const uint8_t *             mcast_addr)
{
    mld_group_t *               mld_group;
    mld_group_t *               first_empty_slot = NULL;
    unsigned int                group_index;

    // Ignore local scope multicast addresses (ff02::/16)
    if (mcast_addr[0] == 0xff && mcast_addr[1] == 0x02)
    {
        return NULL;
    }

    // Look for the group in the fixed group list for the interface
    for (group_index = 0; group_index < mld_interface->group_list_fixed_limit; group_index += 1)
    {
        mld_group = &mld_interface->group_list[group_index];

        // If the group matches, return it
        if (MCB_IP6_ADDR_CMP(mld_group->mcast_addr, mcast_addr) == 0)
        {
            return mld_group;
        }
    }

    // Look for the group in the dynamic group list for the interface
    for (group_index = mld_interface->group_list_fixed_limit; group_index < mld_interface->group_list_count; group_index += 1)
    {
        mld_group = &mld_interface->group_list[group_index];

        // Is this slot active?
        if (mld_group->active)
        {
            // If the group exists, return it
            if (MCB_IP6_ADDR_CMP(mld_group->mcast_addr, mcast_addr) == 0)
            {
                return mld_group;
            }
        }
        else if (first_empty_slot == NULL)
        {
            // Make note the first empty slot we see
            first_empty_slot = mld_group;
        }
    }

    // If the group was not found, and no existing empty slot was seen, see if we can add one
    if (first_empty_slot == NULL)
    {
        // Is the group list full?
        if (mld_interface->group_list_count >= mld_interface->group_list_allocated)
        {
            mld_log(mld_interface, mcast_addr, "Group list full -- group ignored");
            return NULL;
        }

        // Increase the list count
        first_empty_slot = &mld_interface->group_list[mld_interface->group_list_count];
        mld_interface->group_list_count += 1;
    }

    // Set the address
    first_empty_slot->mld_interface = mld_interface;
    MCB_IP6_ADDR_CPY(first_empty_slot->mcast_addr, mcast_addr);

    // NB: The caller will set the active flag
    return first_empty_slot;
}


//
// Handle an MRD solicitation
//
static void handle_mld_mrd_solicitation(
    mld_interface_t *           mld_interface,
    const uint8_t *             ip_src)
{
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, ip_src, src_addr_str, sizeof(src_addr_str));
        logger("MLD(%s) [%s]: received Multicast Router Solicitation\n", mld_interface->name, src_addr_str);
    }

    evm_del_timer(mld_evm, mld_send_mrd_advertisement, mld_interface);
    mld_send_mrd_advertisement(mld_interface);
}


//
// Handle an MLD query
//
static void handle_mld_query(
    mld_interface_t *           mld_interface,
    const uint8_t *             ip_src,
    const mcb_mld_v2_query_t *  query,
    ssize_t                     query_len)
{
    mld_group_t *               mld_group;
    unsigned int                v2_flag = 1;
    unsigned int                new_querier = 0;
    unsigned int                millis;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET6_ADDRSTRLEN] = {0};

    // Is this an MLDv1 query?
    if (query_len < (ssize_t) sizeof(mcb_mld_v2_query_t))
    {
        v2_flag = 0;
    }

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, ip_src, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET6, query->group, group_addr_str, sizeof(group_addr_str));
        logger("MLD(%s) [%s]: received %s query [group %s]\n", mld_interface->name,
            v2_flag ? "v2" : "v1", src_addr_str, group_addr_str);
    }

    // Is the query from someone other than the current querier?
    if (MCB_IP6_ADDR_CMP(ip_src, mld_interface->querier_addr) != 0)
    {
        // Am I the current querier?
        if (MCB_IP6_ADDR_CMP(mld_interface->querier_addr, mld_interface->if_addr) == 0)
        {
            // If the new querier has a lower IP, or the querier mode is "defer", we will
            // defer to the new querier.
            if (MCB_IP6_ADDR_CMP(ip_src, mld_interface->if_addr) < 0 ||
                mld_querier_mode == QUERIER_MODE_DEFER)
            {
                new_querier = 1;
                evm_del_timer(mld_evm, mld_send_general_query, mld_interface);
            }
            else
            {
                // We continue as the querier
                return;
            }
        }
        // Otherwise, does the new querier have a lower IP address than the current querier?
        else if (MCB_IP6_ADDR_CMP(ip_src, mld_interface->querier_addr) < 0)
        {
            new_querier = 1;
        }

        // Is this a new querier?
        if (new_querier)
        {
            // Udate the querier address
            MCB_IP6_ADDR_CPY(mld_interface->querier_addr, ip_src);

            // If this is an MLDv1 query, assume default protcol values
            if (v2_flag == 0)
            {
                mld_interface->querier_robustness = MCB_MLD_ROBUSTNESS;
                mld_interface->querier_interval_sec = MCB_MLD_QUERY_INTERVAL;
                mld_interface->querier_response_interval_millis = MCB_MLD_RESPONSE_INTERVAL;
            }

            mld_log(mld_interface, mld_interface->querier_addr, "New querier elected");
        }
    }

    // Record the current querier values
    if (v2_flag)
    {
        mld_interface->querier_robustness = query->qrv;
        mld_interface->querier_interval_sec = timecode_8bit_decode(query->qqic);
        mld_interface->querier_response_interval_millis = timecode_16bit_decode(ntohs(query->response));
    }

    // Remove the existing quierier timeout timer
    evm_del_timer(mld_evm, mld_querier_timeout, mld_interface);

    // Set a timer to re-enable querying if the active querier times out
    millis = (mld_interface->querier_robustness * mld_interface->querier_interval_sec * 1000 +
              mld_interface->querier_response_interval_millis / 2);
    evm_add_timer(mld_evm, millis, mld_querier_timeout, mld_interface);

    // If the S flag is set, we're done
    if (v2_flag && query->s_flag)
    {
        return;
    }

    // Is it a group specific query?
    if (MCB_IP6_ADDR_CMP(query->group, any_addr) != 0)
    {
        // Find the group
        mld_group = mld_interface_find_group(mld_interface, query->group);
        if (mld_group == NULL)
        {
            return;
        }

        // If the group is not active, ignore the query
        if (mld_group->active == 0)
        {
            return;
        }

        // Remove the existing group membership timer
        evm_del_timer(mld_evm, mld_group_timeout, mld_group);

        // Set the group membership timer
        millis = mld_interface->querier_robustness * mld_interface->querier_response_interval_millis + GRACE_MILLIS;
        evm_add_timer(mld_evm, millis, mld_group_timeout, mld_group);
    }
}


//
// Common join processing
//
static void mld_join_common(
    mld_interface_t *           mld_interface,
    mld_group_t *               mld_group)
{
    unsigned int                interface_index;
    unsigned int                millis;

    // Was the group already active?
    if (mld_group->active)
    {
        // Cancel the existing group timeout
        evm_del_timer(mld_evm, mld_group_timeout, mld_group);
    }
    else
    {
        mld_group->active = 1;

        // Activate the outbound interfaces
        for (interface_index = 0; interface_index < mld_group->bridge_interface_list_count; interface_index += 1)
        {
            interface_activate_outbound(mld_group->bridge_interface_list[interface_index]);
        }
    }

    // Set a timer for the group
    millis = mld_interface->querier_robustness * mld_interface->querier_interval_sec * 1000 +
             mld_interface->querier_response_interval_millis + GRACE_MILLIS;
    evm_add_timer(mld_evm, millis, mld_group_timeout, mld_group);
}


//
// Common leave processing
//
static void mld_leave_common(
    mld_interface_t *           mld_interface,
    mld_group_t *               mld_group)
{
    unsigned int                millis;

    // If I'm not the active querier, ignore the leave
    if (MCB_IP6_ADDR_CMP(mld_interface->querier_addr, mld_interface->if_addr))
    {
        return;
    }

    // If the group is not active, ignore the leave
    if (mld_group->active == 0)
    {
        return;
    }

    // Is a group query series already underway for the group?
    if (mld_group->group_queries_remaining)
    {
        return;
    }

    // Remove the existing group membership timer
    evm_del_timer(mld_evm, mld_group_timeout, mld_group);

    // Set the group membership timer
    millis = mld_interface->querier_robustness * mld_interface->querier_lastmbr_interval_millis + GRACE_MILLIS;
    evm_add_timer(mld_evm, millis, mld_group_timeout, mld_group);

    // Send the first query
    mld_group->group_queries_remaining = mld_interface->querier_robustness;
    send_group_specific_query(mld_group);
}


//
// Handle an MLD v1 report
//
static void handle_mld_v1_report(
    mld_interface_t *           mld_interface,
    const uint8_t *             ip_src,
    const uint8_t *             mcast_addr)
{
    mld_group_t *               mld_group;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET6_ADDRSTRLEN] = {0};

    // Find the group
    mld_group = mld_interface_find_group(mld_interface, mcast_addr);
    if (mld_group == NULL)
    {
        return;
    }

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, ip_src, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET6, mcast_addr, group_addr_str, sizeof(group_addr_str));
        logger("MLD(%s) [%s]: received v1 report [group %s]\n", mld_interface->name, src_addr_str, group_addr_str);
    }

    // Update the group
    mld_join_common(mld_interface, mld_group);
}


//
// Handle an MLD v2 report
//
static void handle_mld_v2_report(
    mld_interface_t *           mld_interface,
    const uint8_t *             ip_src,
    const uint8_t *             mld_buffer,
    unsigned int                mld_len)
{
    mcb_mld_v2_report_t *       mld_report;
    mcb_mld_v2_group_record_t * group_record;
    unsigned int                group_records_remaining;
    mld_group_t *               mld_group;
    unsigned int                record_len;
    unsigned int                num_srcs;
    unsigned int                is_join;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET6_ADDRSTRLEN] = {0};

    // Get the number of records
    mld_report = (mcb_mld_v2_report_t *) mld_buffer;
    mld_buffer += sizeof(mcb_mld_v2_report_t);
    mld_len -= sizeof(mcb_mld_v2_report_t);
    group_records_remaining = ntohs(mld_report->num_groups);

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, ip_src, src_addr_str, sizeof(src_addr_str));
    }

    // Loop through the group records
    while (group_records_remaining)
    {
        // Confirm the packet is long enough for the group record header
        if (mld_len < sizeof(mcb_mld_v2_group_record_t))
        {
            mld_log(mld_interface, ip_src, "Group record header overrun in MLD v2 report");
            return;
        }

        // Get the group record
        group_record = (mcb_mld_v2_group_record_t *) mld_buffer;
        group_records_remaining -= 1;

        // Confirm the packet is long enough for the group record data
        num_srcs = ntohs(group_record->num_srcs);
        record_len = sizeof(mcb_mld_v2_group_record_t) + num_srcs * MCB_IP6_ADDR_LEN + group_record->aux_len * 4;
        if (mld_len < record_len)
        {
            mld_log(mld_interface, ip_src, "Group record data overrun in MLD v2 report");
            return;
        }

        // Consume the group record
        mld_buffer += record_len;
        mld_len -= record_len;

        // Find the group
        mld_group = mld_interface_find_group(mld_interface, group_record->group);
        if (mld_group == NULL)
        {
            continue;
        }

        // Debug logging
        if (debug_level >= 3)
        {
            inet_ntop(AF_INET6, group_record->group, group_addr_str, sizeof(group_addr_str));
            logger("MLD(%s) [%s]: received v2 report type %d [group %s]\n", mld_interface->name,
                src_addr_str, group_record->type, group_addr_str);
        }

        // Check the type to see if it is a join or leave
        is_join = 0;
        switch(group_record->type)
        {
            case MCB_REC_MODE_IS_INCLUDE:
            case MCB_REC_CHANGE_TO_INCLUDE:
                if (group_record->num_srcs)
                {
                    is_join = 1;
                }
                // otherwise is leave
                break;

            case MCB_REC_MODE_IS_EXCLUDE:
            case MCB_REC_CHANGE_TO_EXCLUDE:
            case MCB_REC_ALLOW_NEW_SOURCES:
                is_join = 1;
                break;

            case MCB_REC_BLOCK_OLD_SOURCES:
                if (group_record->num_srcs)
                {
                    return;
                }
                // otherwise is leave
                break;

            default:
                mld_log(mld_interface, ip_src, "Unknown group record type in MLD v2 report");
                return;
        }

        // Update the group
        if (is_join)
        {
            mld_join_common(mld_interface, mld_group);
        }
        else
        {
            mld_leave_common(mld_interface, mld_group);
        }
    }
}


//
// Handle an MLD leave
//
static void handle_mld_v1_leave(
    mld_interface_t *           mld_interface,
    const uint8_t *             ip_src,
    const uint8_t *             mcast_addr)
{
    mld_group_t *               mld_group;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET6_ADDRSTRLEN] = {0};

    // Find the group
    mld_group = mld_interface_find_group(mld_interface, mcast_addr);
    if (mld_group == NULL)
    {
        return;
    }

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET6, ip_src, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET6, mcast_addr, group_addr_str, sizeof(group_addr_str));
        logger("MLD(%s) [%s]: received v1 done [group %s]\n", mld_interface->name, src_addr_str, group_addr_str);
    }

    mld_leave_common(mld_interface, mld_group);
}


//
// Process an incoming packet
//
static void mld_receive(
    void *                      arg)
{
    mld_interface_t *           mld_interface = arg;
    struct pcap_pkthdr          pkthdr;
    const unsigned char *       packet;
    unsigned int                packet_len;
    const mcb_ethernet_t *      eth;
    const mcb_ip6_t *           ip;
    const mcb_ip6_hbh_t *       hop_by_hop;
    const mcb_mld_t *           mld;
    unsigned int                ip_payload_len;
    uint16_t                    calculated_csum;

    // Read the packet
    packet = pcap_next(mld_interface->pcap, &pkthdr);
    if (packet == NULL)
    {
        return;
    }
    packet_len = pkthdr.caplen;

    // Safety check
    if (packet_len < sizeof(mcb_ethernet_t) + sizeof(mcb_ip6_t))
    {
        mld_log(mld_interface, NULL, "Packet too short to contain an IPv6 header");
        return;
    }

    // Parse the ethernet header
    eth = (mcb_ethernet_t *) packet;
    if (ntohs(eth->type) != MCB_ETHERNET_TYPE_IP6)
    {
        mld_log(mld_interface, NULL, "Packet is not an IPv6 packet");
        return;
    }

    // Consume the ethernet header
    packet += sizeof(mcb_ethernet_t);
    packet_len -= sizeof(mcb_ethernet_t);

    // Parse the IPv6 header
    ip = (mcb_ip6_t *) packet;

    // Ignore my own packets
    if (MCB_IP6_ADDR_CMP(ip->src, mld_interface->if_addr) == 0)
    {
        return;
    }

    // Ensure the next header is Hop-by-Hop
    if (ip->next_header != MCB_IP6_OPT_HOP)
    {
        mld_log(mld_interface, ip->src, "Next header in packet is not Hop-by-Hop");
        return;
    }

    // Consume the IPv6 header
    packet += sizeof(mcb_ip6_t);
    packet_len -= sizeof(mcb_ip6_t);

    // Check the payload length
    ip_payload_len = ntohs(ip->payload_len);
    if (ip_payload_len > packet_len)
    {
        mld_log(mld_interface, ip->src, "IP packet overrun");
        return;
    }
    packet_len = ip_payload_len;

    // Confirm the header is long enough for the Hop-by-Hop header
    if (packet_len < sizeof(mcb_ip6_hbh_t))
    {
        mld_log(mld_interface, ip->src, "Packet too short to contain a Hop-by-Hop header");
        return;
    }

    // Parse the Hop-by-Hop header and confirm the Router Alert option
    // NB: The order of RA and PADN options is not guaranteed
    hop_by_hop = (mcb_ip6_hbh_t *) (packet);
    if (hop_by_hop->header_len != 0 || (hop_by_hop->options[0] != MCB_IP6_OPT_RA && hop_by_hop->options[2] != MCB_IP6_OPT_RA))
    {
        mld_log(mld_interface, ip->src, "Packet does not contain a Router Alert option");
        return;
    }

    // Confirm the next header is icmp6
    if (hop_by_hop->next_header != MCB_IP6_PROTO_ICMPV6)
    {
        mld_log(mld_interface, ip->src, "Packet without next header of ICMP6 in Hop-by-Hop header");
        return;
    }

    // Consume the Hop-by-Hop header
    packet += sizeof(mcb_ip6_hbh_t);
    packet_len -= sizeof(mcb_ip6_hbh_t);

    // Confirm the packet is large enough to contain the MLD header
    if (packet_len < sizeof(mcb_mld_t))
    {
        mld_log(mld_interface, ip->src, "Packet too short to contain an MLD header");
        return;
    }

    // Parse the MLD header
    mld = (mcb_mld_t *) packet;

    // Verify the MLD checksum
    calculated_csum = inet6_csum((uint16_t *) mld, packet_len,
        (uint16_t *) ip->src, (uint16_t *) ip->dst, MCB_IP6_PROTO_ICMPV6);
    if (calculated_csum != 0)
    {
        mld_log(mld_interface, ip->src, "ICMP6/MLD checksum error");
        return;
    }

    // Process the MLD packet
    switch (mld->type)
    {
        case MCB_MLD_QUERY:
            handle_mld_query(mld_interface, ip->src, (mcb_mld_v2_query_t *) mld, packet_len);
            break;

        case MCB_MLD_V1_REPORT:
            handle_mld_v1_report(mld_interface, ip->src, mld->group);
            break;

        case MCB_MLD_V1_DONE:
            handle_mld_v1_leave(mld_interface, ip->src, mld->group);
            break;

        case MCB_MLD_V2_REPORT:
            // Confirm the packet is long enough for a v2 report
            if (packet_len < sizeof(mcb_mld_v2_report_t))
            {
                mld_log(mld_interface, ip->src, "Packet too short to contain an MLD v2 report");
                return;
            }
            handle_mld_v2_report(mld_interface, ip->src, (uint8_t *) mld, packet_len);
            break;

        case MCB_MLD_MRD_SOLICITATION:
            handle_mld_mrd_solicitation(mld_interface, ip->src);
            break;

        // NB: MCB_MLD_MRD_ADVERTISEMENT and MCB_MLD_MRD_TERMINATION
        //     are not passed by the pcap filter.
        default:
            mld_log(mld_interface, ip->src, "Unknown MLD type received");
            break;
    }
}


// Pcap
void mld_pcap_create(
    mld_interface_t *           mld_interface)
{
    pcap_t *                    pcap;
    struct bpf_program          program;

    int                         r;
    int                         fd;
    char                        errbuf[PCAP_ERRBUF_SIZE];

    // Create the pcap session
    pcap = pcap_create(mld_interface->name, errbuf);
    if (pcap == NULL)
    {
        fatal("pcap_create for interface %s failed: %s\n", mld_interface->name, errbuf);
    }

    // Set pcap options
    r = pcap_set_snaplen(pcap, MCAST_MAX_PACKET_SIZE);
    if (r != 0)
    {
        fatal("pcap_set_snaplen failed: %d\n", r);
    }
    r = pcap_set_promisc(pcap, 1);
    if (r != 0)
    {
        fatal("pcap_set_promisc failed: %d\n", r);
    }
    r = pcap_set_immediate_mode(pcap, 1);
    if (r != 0)
    {
        fatal("pcap_set_immediate_mode failed: %d\n", r);
    }

    // Activate the pcap session
    r = pcap_activate(pcap);
    if (r < 0)
    {
        fatal("pcap_activate failed: %s\n", pcap_geterr(pcap));
    }

    // Compile the filter
    r = pcap_compile(pcap, &program, MLD_FILTER, 1, PCAP_NETMASK_UNKNOWN);
    if (r == PCAP_ERROR)
    {
        fatal("pcap_compile failed: %s\n", pcap_geterr(pcap));
    }

    // Set the filter
    r = pcap_setfilter(pcap, &program);
    if (r != 0)
    {
        fatal("pcap_setfilter failed: %s\n", pcap_geterr(pcap));
    }
    pcap_freecode(&program);

    // Add the fd to the event manager
    fd = pcap_get_selectable_fd(pcap);
    if (fd < 0)
    {
        fatal("pcap_get_selectable_fd for MLD interface %s failed: %s\n", mld_interface->name, pcap_geterr(pcap));
    }
    evm_add_socket(mld_evm, fd, mld_receive, mld_interface);

    // Store the pcap session
    mld_interface->pcap = pcap;
}


//
// Register a bridge interface for MLD monitoring
//
void mld_register_interface(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    mld_interface_t *           mld_interface;
    mld_group_t *               mld_group;
    unsigned int                interface_index;
    unsigned int                group_index;

    // Is the interface already in the mld interface list?
    for (interface_index = 0; interface_index < mld_interface_list_count; interface_index += 1)
    {
        mld_interface = &mld_interface_list[interface_index];

        if (bridge_interface->if_index == mld_interface->if_index)
        {
            break;
        }
    }

    // If the interface wasn't found, add it
    if (interface_index >= mld_interface_list_count)
    {
        // Do we need to (re)allocate the mld interface list?
        if (interface_index >= mld_interface_list_allocated)
        {
            // Determine the new allocation size
            if (mld_interface_list_allocated == 0)
            {
                mld_interface_list_allocated = 2;
            }
            else
            {
                mld_interface_list_allocated *= 2;
            }

            mld_interface_list = realloc(mld_interface_list, mld_interface_list_allocated * sizeof(mld_interface_t));
            if (mld_interface_list == NULL)
            {
                fatal("Cannot allocate memory for mld interface list: %s\n", strerror(errno));
            }
        }

        // Add the new mld interface to the list
        mld_interface = &mld_interface_list[interface_index];
        mld_interface_list_count += 1;

        // Initialize the new mld interface
        memset(mld_interface, 0, sizeof(*mld_interface));
        mld_interface->name = bridge_interface->name;
        mld_interface->if_index = bridge_interface->if_index;
        MCB_ETH_ADDR_CPY(mld_interface->if_mac_addr, bridge_interface->mac_addr);
        MCB_IP6_ADDR_CPY(mld_interface->if_addr, &bridge_interface->ipv6_addr_ll);
    }

    // Is the group already in the list for this mld interface?
    for (group_index = 0; group_index < mld_interface->group_list_count; group_index += 1)
    {
        mld_group = &mld_interface->group_list[group_index];
        if (MCB_IP6_ADDR_CMP(mld_group->mcast_addr, &bridge->dst_addr.sin6.sin6_addr) == 0)
        {
            break;
        }
    }

    // If the group wasn't found, add it
    if (group_index >= mld_interface->group_list_count)
    {
        // Do we need to (re)allocate the group list?
        if (group_index >= mld_interface->group_list_allocated)
        {
            // Determine the new allocation size
            if (mld_interface->group_list_allocated == 0)
            {
                mld_interface->group_list_allocated = 1;
            }
            else
            {
                mld_interface->group_list_allocated *= 2;
            }

            mld_interface->group_list = realloc(mld_interface->group_list, mld_interface->group_list_allocated * sizeof(mld_group_t));
            if (mld_interface->group_list == NULL)
            {
                fatal("Cannot allocate memory for mld group list: %s\n", strerror(errno));
            }
        }

        // Add a new mld group to the mld interface's list
        mld_group = &mld_interface->group_list[group_index];
        mld_interface->group_list_count += 1;

        // Initialize the new group
        memset(mld_group, 0, sizeof(*mld_group));
        // NB: mld->mld_interface will be set after the group list is finalized
        MCB_IP6_ADDR_CPY(mld_group->mcast_addr, &bridge->dst_addr.sin6.sin6_addr);
    }

    // Do we need to (re)allocate the list of bridge interfaces for this group?
    if (mld_group->bridge_interface_list_count >= mld_group->bridge_interface_list_allocated)
    {
        // Determine the new allocation size
        if (mld_group->bridge_interface_list_allocated == 0)
        {
            mld_group->bridge_interface_list_allocated = 1;
        }
        else
        {
            mld_group->bridge_interface_list_allocated *= 2;
        }

        mld_group->bridge_interface_list = realloc(mld_group->bridge_interface_list, mld_group->bridge_interface_list_allocated * sizeof(bridge_interface_t *));
        if (mld_group->bridge_interface_list == NULL)
        {
            fatal("Cannot allocate memory for mld group list: %s\n", strerror(errno));
        }
    }

    // Add the bridge interface to the list of interfaces for this group
    mld_group->bridge_interface_list[mld_group->bridge_interface_list_count] = bridge_interface;
    mld_group->bridge_interface_list_count += 1;
}


//
// MLD thread
//
__attribute__ ((noreturn))
static void * mld_thread(
    __attribute__ ((unused))
    void *                      arg)
{
    // Run the event loop
    evm_loop(mld_evm);
}


//
// Dump the MLD configuration
//
static void mld_dump_config()
{
    mld_interface_t *           mld_interface;
    mld_group_t *               mld_group;
    unsigned int                interface_index;
    unsigned int                group_index;
    char                        addr_str[INET6_ADDRSTRLEN];

    printf("MLD:\n");
    printf("  Querier Mode: ");
    switch(mld_querier_mode)
    {
        case QUERIER_MODE_NEVER:
            printf("Never\n");
            break;
        case QUERIER_MODE_QUICK:
            printf("Quick\n");
            break;
        case QUERIER_MODE_DELAY:
            printf("Delay\n");
            break;
        case QUERIER_MODE_DEFER:
            printf("Defer\n");
            break;
    }

    for (interface_index = 0; interface_index < mld_interface_list_count; interface_index += 1)
    {
        mld_interface = &mld_interface_list[interface_index];

        printf("  Interface: %s\n", mld_interface->name);
        printf("    if index: %d\n", mld_interface->if_index);
        printf("    hw-addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        mld_interface->if_mac_addr[0], mld_interface->if_mac_addr[1], mld_interface->if_mac_addr[2],
                        mld_interface->if_mac_addr[3], mld_interface->if_mac_addr[4], mld_interface->if_mac_addr[5]);
        printf("    address: %s\n", inet_ntop(AF_INET6, mld_interface->if_addr, addr_str, sizeof(addr_str)));
        printf("    groups:\n");
        for (group_index = 0; group_index < mld_interface->group_list_count; group_index += 1)
        {
            mld_group = &mld_interface->group_list[group_index];
            printf("      %s\n", inet_ntop(AF_INET6, mld_group->mcast_addr, addr_str, sizeof(addr_str)));
        }
    }
}


//
// Initialize the MLD infrastructure
//
void initialize_mld(
    unsigned int                dump_config)
{
    mld_interface_t *           mld_interface;
    mld_group_t *               mld_group;
    unsigned int                interface_index;
    unsigned int                group_index;
    unsigned int                total_groups = 0;

    // Nothing to do if there are no interfaces
    if (mld_interface_list_count < 1)
    {
        return;
    }

    // Dump the MLD configuration
    if (dump_config)
    {
        mld_dump_config();
    }

     // Finalize the interfaces and groups
    for (interface_index = 0; interface_index < mld_interface_list_count; interface_index += 1)
    {
        mld_interface = &mld_interface_list[interface_index];

        // Set the fixed group limit
        mld_interface->group_list_fixed_limit = mld_interface->group_list_count;

        // Adjust the group list size to allow for non configured groups
        mld_interface->group_list_allocated = mld_interface->group_list_count + non_configured_groups;
        mld_interface->group_list = realloc(mld_interface->group_list, mld_interface->group_list_allocated * sizeof(mld_group_t));
        if (mld_interface->group_list == NULL)
        {
            fatal("Cannot allocate memory for mld group list: %s\n", strerror(errno));
        }

        // Initialize the new groups
        memset(&mld_interface->group_list[mld_interface->group_list_count], 0,
            (mld_interface->group_list_allocated - mld_interface->group_list_count) * sizeof(mld_group_t));

        // Now that all the (re)allocation is done, set the interface pointers in the groups
        for (group_index = 0; group_index < mld_interface->group_list_count; group_index += 1)
        {
            mld_group = &mld_interface->group_list[group_index];
            mld_group->mld_interface = mld_interface;
        }

        total_groups += mld_interface->group_list_allocated;
    }

    // Create the event manager
    // NB: The number of timers is a theoretical maximum. In actual use, the number of timers
    //     is expected to be significantly less than half of this number.
    mld_evm = evm_create(mld_interface_list_count, mld_interface_list_count * 2 + total_groups * 2);
    if (mld_evm == NULL)
    {
        fatal("Cannot create event manager\n");
    }

    // Create the pcap instances and register them with the event manager
    for (interface_index = 0; interface_index < mld_interface_list_count; interface_index += 1)
    {
        mld_interface = &mld_interface_list[interface_index];
        mld_pcap_create(mld_interface);
    }
}


//
// Start the MLD thread
//
void start_mld(void)
{
    mld_interface_t *           mld_interface;
    unsigned int                interface_index;
    pthread_t                   thread_id;
    int                         r;

    // Nothing to do if there are no interfaces
    if (mld_interface_list_count < 1)
    {
        return;
    }

    // Set up the querier for each interface
    for (interface_index = 0; interface_index < mld_interface_list_count; interface_index += 1)
    {
        mld_interface = &mld_interface_list[interface_index];

        // Build the multicast router advertisement packet
        mld_build_mrd_advertisement_packet(mld_interface);

        // Send the first multicast router advertisement (no jitter)
        mld_interface->mrd_initial_advertisements_remaining = MCB_MRD_INITIAL_COUNT - 1;
        mld_send_mrd_advertisement(mld_interface);

        // Build the query packets
        mld_build_query_packets(mld_interface);

        // Is quick querier mode enabled?
        if (mld_querier_mode == QUERIER_MODE_QUICK)
        {
            mld_activate_querier_mode(mld_interface);
        }
        else
        {
            // Set default querier values
            mld_interface->querier_robustness = MCB_MLD_ROBUSTNESS;
            mld_interface->querier_interval_sec = MCB_MLD_QUERY_INTERVAL;
            mld_interface->querier_response_interval_millis = MCB_MLD_RESPONSE_INTERVAL;
            mld_interface->querier_lastmbr_interval_millis = MCB_MLD_LASTMBR_INTERVAL;

            // Set the querier address to all ones allowing anyone to win an election
            MCB_IP6_ADDR_SET(mld_interface->querier_addr, 0xff);

            // Is querier mode enabled?
            if (mld_querier_mode)
            {
                // Set a timer to activate as a quierier (125.5 seconds)
                evm_add_timer(mld_evm, 125500, mld_querier_timeout, mld_interface);
            }
        }
    }

    // Start the thread
    r = pthread_create(&thread_id, NULL, &mld_thread, NULL);
    if (r != 0)
    {
        fatal("cannot create MLD thread: %s\n", strerror(errno));
    }
}
