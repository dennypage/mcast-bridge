
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
// The IGMP implementation herein is primarily based on RFC 2236 and RFC 9976.
//
// The implementation deviates from the standards in the following aspects:
//
//  1. The implementation ignores all link-local scope multicast addresses (224.0.0.0/24).
//
//  2. The IGMPv3 implementation works at the IP group level only, ignoring all source
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
//     Multicast Router Discovery Advertisement message, however subsequent initial
//     advertisements are sent with a random interval.
//  2. No Multicast Router Discovery Termination messages are sent.
//



// Pcap IGMP filter
//
//   Expected Packet format:
//     Ethernet header
//     IPv4 header
//     Router Alert header
//     IGMP header
//
#define IGMP_FILTER             "igmp"

// Buffer sizes
#define IGMP_MRD_BUFFER_SIZE    (sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t) + sizeof(mcb_mrd_advertisement_t))
#define IGMP_QUERY_BUFFER_SIZE  (sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t) + sizeof(mcb_igmp_v3_query_t))

// Grace period for protocol timeouts in milliseconds
#define GRACE_MILLIS            10


// IGMP group structure
typedef struct igmp_interface   igmp_interface_t;
typedef struct igmp_group
{
    // The igmp interface this group belongs to
    igmp_interface_t *          igmp_interface;

    // Bridge interface list
    bridge_interface_t **       bridge_interface_list;
    unsigned int                bridge_interface_list_allocated;
    unsigned int                bridge_interface_list_count;

    // Is the group currently active?
    unsigned int                active;

    // Group address
    uint8_t                     mcast_addr[MCB_IP4_ADDR_LEN];

    // IGMP parameters
    unsigned int                v1_host_present;
    unsigned int                group_queries_remaining;
} igmp_group_t;

// IGMP interface structure
typedef struct igmp_interface
{
    // IGMP groups
    igmp_group_t *              group_list;
    unsigned int                group_list_allocated;
    unsigned int                group_list_count;
    unsigned int                group_list_fixed_limit;

    // Interface name, index and address
    char *                      name;
    unsigned int                if_index;
    uint8_t                     if_addr[MCB_IP4_ADDR_LEN];
    uint8_t                     if_mac_addr[MCB_ETH_ADDR_LEN];

    // Pcap handle
    pcap_t *                    pcap;

    // Current IGMP querier variables
    uint8_t                     querier_addr[MCB_IP4_ADDR_LEN];
    unsigned int                querier_robustness;
    unsigned int                querier_interval_sec;
    unsigned int                querier_response_interval_tenths;
    unsigned int                querier_lastmbr_interval_tenths;

    // Number of initial multicast router advertisements remaining
    unsigned int                mrd_initial_advertisements_remaining;

    // Number of startup queries remaining
    unsigned int                startup_queries_remaining;

    // Packet for multicast router advertisements
    uint8_t                     mrd_advertisement_packet[IGMP_MRD_BUFFER_SIZE];

    // Packets for general and group specific queries
    uint8_t                     general_query_packet[IGMP_QUERY_BUFFER_SIZE];
    uint8_t                     specific_query_packet[IGMP_QUERY_BUFFER_SIZE];
} igmp_interface_t;


// IGMP event manager
static evm_t *                  igmp_evm;

// IGMP interface list
static igmp_interface_t *       igmp_interface_list = NULL;
static unsigned int             igmp_interface_list_allocated = 0;
static unsigned int             igmp_interface_list_count = 0;

// Special addresses
static uint8_t                  any_addr[MCB_IP4_ADDR_LEN] = MCB_IP4_ANY;
static uint8_t                  allhosts_addr[MCB_IP4_ADDR_LEN];
static uint8_t                  allsnoopers_addr[MCB_IP4_ADDR_LEN];

// Random number state
static unsigned short           random_state[3];



//
// Log an IGMP issue
//
static void igmp_log(
    const igmp_interface_t *    igmp_interface,
    const uint8_t *             addr,
    const char *                msg)
{
    char                        addr_str[INET_ADDRSTRLEN] = {0};

    // Minimum debug log level
    if (debug_level < 2)
    {
        return;
    }

    // Format the address
    if (addr)
    {
        inet_ntop(AF_INET, addr, addr_str, sizeof(addr_str));
    }

    logger("IGMP(%s) [%s]: %s\n", igmp_interface->name, addr_str, msg);
}


//
// Build the multicast router advertisement packet
//
static void igmp_build_mrd_advertisement_packet(
    igmp_interface_t *          igmp_interface)
{
    mcb_ethernet_t *            ethernet;
    mcb_ip4_t *                 ip;
    mcb_ip4_ra_opt_t *          ip_ra;
    mcb_mrd_advertisement_t *   mrd_advertisement;
    uint8_t                     buffer[IGMP_MRD_BUFFER_SIZE];

    // Initialize the buffer
    memset(buffer, 0, sizeof(buffer));

    // Pointers to the individual headers
    ethernet = (mcb_ethernet_t *) buffer;
    ip = (mcb_ip4_t *) (buffer + sizeof(mcb_ethernet_t));
    ip_ra = (mcb_ip4_ra_opt_t *) (buffer + sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t));
    mrd_advertisement = (mcb_mrd_advertisement_t *) (buffer + (sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t)));

    // Build the Ethernet header
    ethernet->type = htons(MCB_ETHERNET_TYPE_IP4);
    // NB: The format of the dst addr for IPv4 multicast is 01:00:5e:XX:XX:XX where
    // XX:XX:XX is the last 23 bits of the IP4 multicast address.
    ethernet->dst[0] = 0x01;
    ethernet->dst[1] = 0x00;
    ethernet->dst[2] = 0x5e;
    ethernet->dst[3] = allsnoopers_addr[1] & 0x7f;
    ethernet->dst[4] = allsnoopers_addr[2];
    ethernet->dst[5] = allsnoopers_addr[3];
    MCB_ETH_ADDR_CPY(ethernet->src, igmp_interface->if_mac_addr);

    // Build the IP header
    ip->version = 4;
    ip->header_len = (sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t)) >> 2;
    ip->total_len = htons(sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t) + sizeof(mcb_mrd_advertisement_t));
    ip->offset = htons(MCB_IP4_OFF_DF);
    ip->tos = MCB_IP4_TOS_IC;
    ip->ttl = 1;
    ip->protocol = IPPROTO_IGMP;
    MCB_IP4_ADDR_CPY(ip->src, igmp_interface->if_addr);
    MCB_IP4_ADDR_CPY(ip->dst, allsnoopers_addr);

    // Build the IP Router Alert option
    ip_ra->type = MCB_IP4_OPT_RA;
    ip_ra->length = 4;
    ip_ra->value = 0;

    // Build the MRD Advertisement
    mrd_advertisement->type = MCB_IGMP_MRD_ADVERTISEMENT;
    mrd_advertisement->interval = MCB_MRD_INTERVAL;
    mrd_advertisement->qqi = htons(MCB_IGMP_QUERY_INTERVAL);
    mrd_advertisement->qrv = htons(MCB_IGMP_ROBUSTNESS);

    // Set the checksums
    ip->csum = inet_csum((uint16_t *) ip, sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t));
    mrd_advertisement->csum = inet_csum((uint16_t *) mrd_advertisement, sizeof(*mrd_advertisement));
    memcpy(igmp_interface->mrd_advertisement_packet, buffer, sizeof(igmp_interface->mrd_advertisement_packet));
}


//
// Build the general and group specific query packets for an interface
//
static void igmp_build_query_packets(
    igmp_interface_t *          igmp_interface)
{
    mcb_ethernet_t *            ethernet;
    mcb_ip4_t *                 ip;
    mcb_ip4_ra_opt_t *          ip_ra;
    mcb_igmp_v3_query_t *       igmp_query;
    uint8_t                     buffer[IGMP_QUERY_BUFFER_SIZE];

    // Initialize the buffer
    memset(buffer, 0, sizeof(buffer));

    // Pointers to the individual headers
    ethernet = (mcb_ethernet_t *) buffer;
    ip = (mcb_ip4_t *) (buffer + sizeof(mcb_ethernet_t));
    ip_ra = (mcb_ip4_ra_opt_t *) (buffer + sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t));
    igmp_query = (mcb_igmp_v3_query_t *) (buffer + (sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t)));

    // Build the Ethernet header
    ethernet->type = htons(MCB_ETHERNET_TYPE_IP4);
    // NB: The format of the dst addr for IPv4 multicast is 01:00:5e:XX:XX:XX where
    // XX:XX:XX is the last 23 bits of the IP4 multicast address. The bottom 3 bytes
    // of the address and will be filled in later.
    ethernet->dst[0] = 0x01;
    ethernet->dst[1] = 0x00;
    ethernet->dst[2] = 0x5e;
    MCB_ETH_ADDR_CPY(ethernet->src, igmp_interface->if_mac_addr);

    // Build the IP header
    ip->version = 4;
    ip->header_len = (sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t)) >> 2;
    ip->total_len = htons(sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t) + sizeof(mcb_igmp_v3_query_t));
    ip->offset = htons(MCB_IP4_OFF_DF);
    ip->tos = MCB_IP4_TOS_IC;
    ip->ttl = 1;
    ip->protocol = IPPROTO_IGMP;
    MCB_IP4_ADDR_CPY(ip->src, igmp_interface->if_addr);

    // Build the IP Router Alert option
    ip_ra->type = MCB_IP4_OPT_RA;
    ip_ra->length = 4;
    ip_ra->value = 0;

    // Build the IGMP v3 query header
    igmp_query->type = MCB_IGMP_QUERY;
    igmp_query->qrv = MCB_IGMP_ROBUSTNESS;
    igmp_query->qqic = MCB_IGMP_QUERY_INTERVAL;

    // Set up the group specific query packet
    // NB: ip->dst, ip->csum, igmp->igmp_group and igmp->csum are finalized in send_group_specific_query()
    igmp_query->code = MCB_IGMP_LASTMBR_INTERVAL;
    memcpy(igmp_interface->specific_query_packet, buffer, sizeof(igmp_interface->specific_query_packet));

    // Set up the general query packet
    ethernet->dst[3] = allhosts_addr[1] & 0x7f;
    ethernet->dst[4] = allhosts_addr[2];
    ethernet->dst[5] = allhosts_addr[3];
    MCB_IP4_ADDR_CPY(ip->dst, allhosts_addr);
    ip->csum = inet_csum((uint16_t *) ip, sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t));
    igmp_query->code = MCB_IGMP_RESPONSE_INTERVAL;
    igmp_query->csum = inet_csum((uint16_t *) igmp_query, sizeof(*igmp_query));
    memcpy(igmp_interface->general_query_packet, buffer, sizeof(igmp_interface->general_query_packet));
}


//
// Send a multicast router advertisement
//
static void igmp_send_mrd_advertisement(
    void *                      arg)
{
    igmp_interface_t *          igmp_interface = (igmp_interface_t *) arg;
    unsigned int                millis;
    int                         r;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, igmp_interface->if_addr, src_addr_str, sizeof(src_addr_str));
        logger("IGMP(%s) [%s]: sending Multicast Router Discovery advertisement\n", igmp_interface->name, src_addr_str);
    }

    r = pcap_inject(igmp_interface->pcap, igmp_interface->mrd_advertisement_packet, sizeof(igmp_interface->mrd_advertisement_packet));
    if (r == PCAP_ERROR)
    {
        logger("IGMP(%s): pcap_inject failed: %s\n", igmp_interface->name, pcap_geterr(igmp_interface->pcap));
    }

    // Set the next advertisement interval
    if (igmp_interface->mrd_initial_advertisements_remaining)
    {
        // Are we in startup mode?
        igmp_interface->mrd_initial_advertisements_remaining -= 1;
        millis = MCB_MRD_INITIAL_INTERVAL_MS(random_state);
    }
    else
    {
        millis = MCB_MRD_INTERVAL_MS(random_state);
    }

    // Set a timer for the next advertisement
    evm_add_timer(igmp_evm, millis, igmp_send_mrd_advertisement, igmp_interface);
}


//
// Send a general query
//
static void igmp_send_general_query(
    void *                      arg)
{
    igmp_interface_t *          igmp_interface = (igmp_interface_t *) arg;
    unsigned int                millis;
    int                         r;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, igmp_interface->if_addr, src_addr_str, sizeof(src_addr_str));
        logger("IGMP(%s) [%s]: sending general query\n", igmp_interface->name, src_addr_str);
    }

    // Send the query
    r = pcap_inject(igmp_interface->pcap, igmp_interface->general_query_packet, sizeof(igmp_interface->general_query_packet));
    if (r == PCAP_ERROR)
    {
        logger("IGMP(%s): pcap_inject failed: %s\n", igmp_interface->name, pcap_geterr(igmp_interface->pcap));
    }

    // Set the next query interval
    millis = igmp_interface->querier_interval_sec * 1000;
    if (igmp_interface->startup_queries_remaining)
    {
        // Are we in startup mode?
        igmp_interface->startup_queries_remaining -= 1;
        millis /= 4;
    }

    // Set a timer for the next query
    evm_add_timer(igmp_evm, millis, igmp_send_general_query, igmp_interface);
}


//
// Send a group specific query
//
static void send_group_specific_query(
    void *                      arg)
{
    igmp_group_t *              igmp_group = (igmp_group_t *) arg;
    igmp_interface_t *          igmp_interface = igmp_group->igmp_interface;
    uint8_t *                   mcast_addr = igmp_group->mcast_addr;
    mcb_ethernet_t *            ethernet;
    mcb_ip4_t *                 ip;
    mcb_igmp_v3_query_t *       igmp_query;
    int                         r;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, igmp_interface->if_addr, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET, mcast_addr, group_addr_str, sizeof(group_addr_str));
        logger("IGMP(%s) [%s]: sending query [group %s]\n", igmp_interface->name, src_addr_str, group_addr_str);
    }

    // Pointers to the individual headers
    ethernet = (mcb_ethernet_t *) igmp_interface->specific_query_packet;
    ip = (mcb_ip4_t *) (igmp_interface->specific_query_packet + sizeof(mcb_ethernet_t));
    igmp_query = (mcb_igmp_v3_query_t *) (igmp_interface->specific_query_packet + sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t));

    // Set the remaining 3 bytes of the ethernet destination address
    ethernet->dst[3] = mcast_addr[1] & 0x7f;
    ethernet->dst[4] = mcast_addr[2];
    ethernet->dst[5] = mcast_addr[3];

    // Set the ip destination and igmp group
    MCB_IP4_ADDR_CPY(ip->dst, mcast_addr);
    MCB_IP4_ADDR_CPY(igmp_query->group, mcast_addr);

    // Set the S flag as appropriate
    if (igmp_group->group_queries_remaining ==  igmp_interface->querier_robustness)
    {
        igmp_query->s_flag = 0;
    }
    else
    {
        igmp_query->s_flag = 1;
    }

    // Calculate the IP and IGMP checksums
    ip->csum = 0;
    ip->csum = inet_csum((uint16_t *) ip, sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t));
    igmp_query->csum = 0;
    igmp_query->csum = inet_csum((uint16_t *) igmp_query, sizeof(*igmp_query));

    // Send the query
    r = pcap_inject(igmp_interface->pcap, igmp_interface->specific_query_packet, sizeof(igmp_interface->specific_query_packet));
    if (r == PCAP_ERROR)
    {
        logger("IGMP(%s): pcap_inject failed: %s\n", igmp_interface->name, pcap_geterr(igmp_interface->pcap));
    }

    // Do we need to send more?
    igmp_group->group_queries_remaining -= 1;
    if (igmp_group->group_queries_remaining)
    {
        evm_add_timer(igmp_evm, igmp_interface->querier_lastmbr_interval_tenths * 100, send_group_specific_query, igmp_group);
        return;
    }
}


//
// Activate querier mode
//
static void igmp_activate_querier_mode(
    igmp_interface_t  *         igmp_interface)
{
    igmp_log(igmp_interface, igmp_interface->if_addr, "Querier mode activated");

    // Set the querier parameters
    igmp_interface->querier_robustness = MCB_IGMP_ROBUSTNESS;
    igmp_interface->querier_interval_sec = MCB_IGMP_QUERY_INTERVAL;
    igmp_interface->querier_response_interval_tenths = MCB_IGMP_RESPONSE_INTERVAL;
    igmp_interface->querier_lastmbr_interval_tenths = MCB_IGMP_LASTMBR_INTERVAL;

    // Set my address as the querier
    MCB_IP4_ADDR_CPY(igmp_interface->querier_addr, igmp_interface->if_addr);

    // Send the first general query
    igmp_interface->startup_queries_remaining = igmp_interface->querier_robustness - 1;
    igmp_send_general_query(igmp_interface);
}


//
// IGMP querier timeout
//
static void igmp_querier_timeout(
    void *                      arg)
{
    igmp_interface_t *          igmp_interface = (igmp_interface_t *) arg;

    igmp_log(igmp_interface, igmp_interface->querier_addr, "Querier timeout");

    if (igmp_querier_mode)
    {
        // Activate as the querier
        igmp_activate_querier_mode(igmp_interface);
    }
    else
    {
        igmp_log(igmp_interface, igmp_interface->if_addr, "Querier mode disabled");

        // Reset the querier address to all ones
        MCB_IP4_ADDR_SET(igmp_interface->querier_addr, 0xff);
    }
}


//
// IGMP group timeout
//
static void igmp_group_timeout(
    void *                      arg)
{
    igmp_group_t *              igmp_group = arg;
    igmp_interface_t *          igmp_interface = igmp_group->igmp_interface;
    unsigned int                group_index;
    unsigned int                bridge_interface_index;

    igmp_log(igmp_interface, igmp_group->mcast_addr, "Group membership timeout");

    // Mark the group as inactive
    igmp_group->active = 0;

    // Is this one of the registered groups?
    if (igmp_group->bridge_interface_list_count)
    {
        // deactivate the outbound interfaces
        for (bridge_interface_index = 0; bridge_interface_index < igmp_group->bridge_interface_list_count; bridge_interface_index += 1)
        {
            interface_deactivate_outbound(igmp_group->bridge_interface_list[bridge_interface_index]);
        }
        return;
    }

    // Tighten up the group list count if possible
    for (group_index = igmp_interface->group_list_count - 1; group_index > igmp_interface->group_list_fixed_limit; group_index -= 1)
    {
        if (igmp_interface->group_list[group_index].active)
        {
            break;
        }
        igmp_interface->group_list_count -= 1;
    }
}


//
// IGMP v1 host present timeout
//
static void igmp_v1_host_timeout(
    void *                      arg)
{
    igmp_group_t *              igmp_group = arg;

    // Debug logging
    if (debug_level >= 3)
    {
        logger("IGMP(%s) []: v1 host present timeout\n", igmp_group->igmp_interface->name);
    }

    igmp_group->v1_host_present = 0;
}


//
// Find a group in the group list for an interface
//
static igmp_group_t * igmp_interface_find_group(
    igmp_interface_t *          igmp_interface,
    const uint8_t *             mcast_addr)
{
    igmp_group_t *              igmp_group;
    igmp_group_t *              first_empty_slot = NULL;
    unsigned int                group_index;

    // Ignore local scope multicast addresses (224.0.0.0/24)
    if ((mcast_addr[0] & 0xff) == 0xe0 && mcast_addr[1] == 0x00 && mcast_addr[2] == 0x00)
    {
            return NULL;
    }

    // Look for the group in the fixed group list for the interface
    for (group_index = 0; group_index < igmp_interface->group_list_fixed_limit; group_index += 1)
    {
        igmp_group = &igmp_interface->group_list[group_index];

        // If the group matches, return it
        if (MCB_IP4_ADDR_CMP(igmp_group->mcast_addr, mcast_addr) == 0)
        {
            return igmp_group;
        }
    }

    // Look for the group in the dynamic group list for the interface
    for (group_index = igmp_interface->group_list_fixed_limit; group_index < igmp_interface->group_list_count; group_index += 1)
    {
        igmp_group = &igmp_interface->group_list[group_index];

        // Is this slot active?
        if (igmp_group->active)
        {
            // If the group exists, return it
            if (MCB_IP4_ADDR_CMP(igmp_group->mcast_addr, mcast_addr) == 0)
            {
                return igmp_group;
            }
        }
        else if (first_empty_slot == NULL)
        {
            // Make note the first empty slot we see
            first_empty_slot = igmp_group;
        }
    }

    // If the group was not found, and no existing empty slot was seen, see if we can add one
    if (first_empty_slot == NULL)
    {
        // Is the group list full?
        if (igmp_interface->group_list_count >= igmp_interface->group_list_allocated)
        {
            igmp_log(igmp_interface, mcast_addr, "Group list full -- group ignored");
            return NULL;
        }

        // Increase the list count
        first_empty_slot = &igmp_interface->group_list[igmp_interface->group_list_count];
        igmp_interface->group_list_count += 1;
    }

    // Set the address
    first_empty_slot->igmp_interface = igmp_interface;
    MCB_IP4_ADDR_CPY(first_empty_slot->mcast_addr, mcast_addr);

    // NB: The caller will set the active flag
    return first_empty_slot;
}


//
// Handle an MRD solicitation
//
static void handle_igmp_mrd_solicitation(
    igmp_interface_t *          igmp_interface,
    const uint8_t *             ip_src)
{
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, ip_src, src_addr_str, sizeof(src_addr_str));
        logger("IGMP(%s) [%s]: received Multicast Router Solicitation\n", igmp_interface->name, src_addr_str);
    }

    evm_del_timer(igmp_evm, igmp_send_mrd_advertisement, igmp_interface);
    igmp_send_mrd_advertisement(igmp_interface);
}


//
// Handle an IGMP query
//
static void handle_igmp_query(
    igmp_interface_t *          igmp_interface,
    const uint8_t *             ip_src,
    const uint8_t *             igmp_buffer,
    unsigned int                igmp_len)
{
    const mcb_igmp_v3_query_t * query = (mcb_igmp_v3_query_t *) igmp_buffer;
    igmp_group_t *              igmp_group;
    unsigned int                v3_flag = 1;
    unsigned int                new_querier = 0;
    unsigned int                millis;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET_ADDRSTRLEN] = {0};

    // Confirm the packet is large enough to contain a query
    if (igmp_len < sizeof(mcb_igmp_t))
    {
        igmp_log(igmp_interface, ip_src, "Packet too short to contain an IGMP query");
        return;
    }

    // Is this an IGMPv2/1 query?
    if (igmp_len < sizeof(mcb_igmp_v3_query_t))
    {
        v3_flag = 0;
    }

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, ip_src, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET, query->group, group_addr_str, sizeof(group_addr_str));
        logger("IGMP(%s) [%s]: received %s query [group %s]\n", igmp_interface->name,
            v3_flag ? "v3" : "v2", src_addr_str, group_addr_str);
    }

    // Is the query from someone other than the current querier?
    if (MCB_IP4_ADDR_CMP(ip_src, igmp_interface->querier_addr) != 0)
    {
        // Am I the current querier?
        if (MCB_IP4_ADDR_CMP(igmp_interface->querier_addr, igmp_interface->if_addr) == 0)
        {
            // If the new querier has a lower IP, or the querier mode is "defer", we will
            // defer to the new querier.
            if (MCB_IP4_ADDR_CMP(ip_src, igmp_interface->if_addr) < 0 ||
                igmp_querier_mode == QUERIER_MODE_DEFER)
            {
                new_querier = 1;
                evm_del_timer(igmp_evm, igmp_send_general_query, igmp_interface);
            }
            else
            {
                // We continue as the querier
                return;
            }
        }
        // Otherwise, does the new querier have a lower IP address than the current querier?
        else if (MCB_IP4_ADDR_CMP(ip_src, igmp_interface->querier_addr) < 0)
        {
            new_querier = 1;
        }

        // Is this a new querier?
        if (new_querier)
        {
            // Update the querier address
            MCB_IP4_ADDR_CPY(igmp_interface->querier_addr, ip_src);

            // If this is an IGMPv1/IGMPv2 query, assume default protocol values
            if (v3_flag == 0)
            {
                igmp_interface->querier_robustness = MCB_IGMP_ROBUSTNESS;
                igmp_interface->querier_interval_sec = MCB_IGMP_QUERY_INTERVAL;
                igmp_interface->querier_response_interval_tenths = MCB_IGMP_RESPONSE_INTERVAL;
            }

            igmp_log(igmp_interface, igmp_interface->querier_addr, "New querier elected");
        }
    }

    // Record the current querier values
    if (v3_flag)
    {
        igmp_interface->querier_robustness = query->qrv;
        igmp_interface->querier_interval_sec = timecode_8bit_decode(query->qqic);
        igmp_interface->querier_response_interval_tenths = timecode_8bit_decode(query->code);
    }

    // Remove the existing querier timeout timer
    evm_del_timer(igmp_evm, igmp_querier_timeout, igmp_interface);

    // Set a timer to re-enable querying if the active querier times out
    millis = (igmp_interface->querier_robustness *
              igmp_interface->querier_interval_sec +
              igmp_interface->querier_response_interval_tenths / 20) * 1000;
    evm_add_timer(igmp_evm, millis, igmp_querier_timeout, igmp_interface);

    // If the S flag is set, we're done
    if (v3_flag && query->s_flag)
    {
        return;
    }

    // Is it a group specific query?
    if (MCB_IP4_ADDR_CMP(query->group, any_addr) != 0)
    {
        // Find the group
        igmp_group = igmp_interface_find_group(igmp_interface, query->group);
        if (igmp_group == NULL)
        {
            return;
        }

        // If the group is not active, ignore the query
        if (igmp_group->active == 0)
        {
            return;
        }

        // Remove the existing group membership timer
        evm_del_timer(igmp_evm, igmp_group_timeout, igmp_group);

        // Set the group membership timer
        millis = igmp_interface->querier_robustness * igmp_interface->querier_response_interval_tenths * 100 + GRACE_MILLIS;
        evm_add_timer(igmp_evm, millis, igmp_group_timeout, igmp_group);
    }
}


//
// Common join processing
//
static void igmp_join_common(
    igmp_interface_t *          igmp_interface,
    igmp_group_t *              igmp_group)
{
    unsigned int                interface_index;
    unsigned int                millis;

    // Was the group already active?
    if (igmp_group->active)
    {
        // Cancel the existing group timeout
        evm_del_timer(igmp_evm, igmp_group_timeout, igmp_group);
    }
    else
    {
        igmp_group->active = 1;

        // Activate the outbound interfaces
        for (interface_index = 0; interface_index < igmp_group->bridge_interface_list_count; interface_index += 1)
        {
            interface_activate_outbound(igmp_group->bridge_interface_list[interface_index]);
        }
    }

    // Set a timer for the group
    millis = (igmp_interface->querier_robustness * igmp_interface->querier_interval_sec +
              igmp_interface->querier_response_interval_tenths / 10) * 1000;
    evm_add_timer(igmp_evm, millis, igmp_group_timeout, igmp_group);
}


//
// Common leave processing
//
static void igmp_leave_common(
    igmp_interface_t *          igmp_interface,
    igmp_group_t *              igmp_group)
{
    unsigned int                millis;

    // If I'm not the active querier, ignore the leave
    if (MCB_IP4_ADDR_CMP(igmp_interface->querier_addr, igmp_interface->if_addr))
    {
        return;
    }

    // If the group is not active, ignore the leave
    if (igmp_group->active == 0)
    {
        return;
    }

    // If a v1 host is present, ignore the leave and do not send group specific queries
    if (igmp_group->v1_host_present)
    {
        return;
    }

    // Is a group query series already underway for the group?
    if (igmp_group->group_queries_remaining)
    {
        return;
    }

    // Remove the existing group membership timer
    evm_del_timer(igmp_evm, igmp_group_timeout, igmp_group);

    // Set the group membership timer
    millis = igmp_interface->querier_robustness * igmp_interface->querier_lastmbr_interval_tenths * 100 + GRACE_MILLIS;
    evm_add_timer(igmp_evm, millis, igmp_group_timeout, igmp_group);

    // Send the first query
    igmp_group->group_queries_remaining = igmp_interface->querier_robustness;
    send_group_specific_query(igmp_group);
}


//
// Handle an IGMP v1 report
//
static void handle_igmp_v1_report(
    igmp_interface_t *          igmp_interface,
    const uint8_t *             ip_src,
    const uint8_t *             igmp_buffer,
    unsigned int                igmp_len)
{
    mcb_igmp_t *                igmp = (mcb_igmp_t *) igmp_buffer;
    igmp_group_t *              igmp_group;
    unsigned int                millis;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET_ADDRSTRLEN] = {0};

    // Confirm the packet is large enough to contain the report
    if (igmp_len < sizeof(mcb_igmp_t))
    {
        igmp_log(igmp_interface, ip_src, "Packet too short to contain an IGMP v1 report");
        return;
    }

    // Find the group
    igmp_group = igmp_interface_find_group(igmp_interface, igmp->group);
    if (igmp_group == NULL)
    {
        return;
    }

    // Set or update the v1 host present timer
    if (igmp_group->active && igmp_group->v1_host_present)
    {
        // Remove the existing v1 host presence timer
        evm_del_timer(igmp_evm, igmp_v1_host_timeout, igmp_group);
    }
    else
    {
        igmp_group->v1_host_present = 1;
    }

    // Set a timer for the v1 host presence
    millis = (igmp_interface->querier_robustness * igmp_interface->querier_interval_sec +
              igmp_interface->querier_response_interval_tenths / 10) * 1000;
    evm_add_timer(igmp_evm, millis, igmp_v1_host_timeout, igmp_group);

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, ip_src, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET, igmp->group, group_addr_str, sizeof(group_addr_str));
        logger("IGMP(%s) [%s]: received v1 report [group %s]\n", igmp_interface->name, src_addr_str, group_addr_str);
    }

    // Update the group
    igmp_join_common(igmp_interface, igmp_group);
}


//
// Handle an IGMP v2 report
//
static void handle_igmp_v2_report(
    igmp_interface_t *          igmp_interface,
    const uint8_t *             ip_src,
    const uint8_t *             igmp_buffer,
    unsigned int                igmp_len)
{
    mcb_igmp_t *                igmp = (mcb_igmp_t *) igmp_buffer;
    igmp_group_t *              igmp_group;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET_ADDRSTRLEN] = {0};

    // Confirm the packet is large enough to contain the report
    if (igmp_len < sizeof(mcb_igmp_t))
    {
        igmp_log(igmp_interface, ip_src, "Packet too short to contain an IGMP v2 report");
        return;
    }

    // Find the group
    igmp_group = igmp_interface_find_group(igmp_interface, igmp->group);
    if (igmp_group == NULL)
    {
        return;
    }

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, ip_src, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET, igmp->group, group_addr_str, sizeof(group_addr_str));
        logger("IGMP(%s) [%s]: received v2 report [group %s]\n", igmp_interface->name, src_addr_str, group_addr_str);
    }

    // Update the group
    igmp_join_common(igmp_interface, igmp_group);
}


//
// Handle an IGMP v3 report
//
static void handle_igmp_v3_report(
    igmp_interface_t *          igmp_interface,
    const uint8_t *             ip_src,
    const uint8_t *             igmp_buffer,
    unsigned int                igmp_len)
{
    mcb_igmp_v3_report_t *      igmp_report;
    mcb_igmp_v3_group_record_t *group_record;
    unsigned int                group_records_remaining;
    igmp_group_t *              igmp_group;
    unsigned int                record_len;
    unsigned int                num_srcs;
    unsigned int                is_join;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET_ADDRSTRLEN] = {0};

    // Confirm the packet is large enough to contain the report
    if (igmp_len < sizeof(mcb_igmp_v3_report_t))
    {
        igmp_log(igmp_interface, ip_src, "Packet too short to contain an IGMP v3 report");
        return;
    }

    // Get the number of records
    igmp_report = (mcb_igmp_v3_report_t *) igmp_buffer;
    igmp_buffer += sizeof(mcb_igmp_v3_report_t);
    igmp_len -= sizeof(mcb_igmp_v3_report_t);
    group_records_remaining = ntohs(igmp_report->num_groups);

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, ip_src, src_addr_str, sizeof(src_addr_str));
    }

    // Loop through the group records
    while (group_records_remaining)
    {
        // Confirm the packet is long enough for the group record header
        if (igmp_len < sizeof(mcb_igmp_v3_group_record_t))
        {
            igmp_log(igmp_interface, ip_src, "Group record header overrun in IGMP v3 report");
            return;
        }

        // Get the group record
        group_record = (mcb_igmp_v3_group_record_t *) igmp_buffer;
        group_records_remaining -= 1;

        // Confirm the packet is long enough for the group record data
        num_srcs = ntohs(group_record->num_srcs);
        record_len = sizeof(mcb_igmp_v3_group_record_t) + num_srcs * MCB_IP4_ADDR_LEN + group_record->aux_len * 4;
        if (igmp_len < record_len)
        {
            igmp_log(igmp_interface, ip_src, "Group record data overrun in IGMP v3 report");
            return;
        }

        // Consume the group record
        igmp_buffer += record_len;
        igmp_len -= record_len;

        // Find the group
        igmp_group = igmp_interface_find_group(igmp_interface, group_record->group);
        if (igmp_group == NULL)
        {
            continue;
        }

        // Debug logging
        if (debug_level >= 3)
        {
            inet_ntop(AF_INET, group_record->group, group_addr_str, sizeof(group_addr_str));
            logger("IGMP(%s) [%s]: received v3 report type %d [group %s]\n", igmp_interface->name,
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
                igmp_log(igmp_interface, ip_src, "Unknown group record type in IGMP v3 report");
                return;
        }

        // Update the group
        if (is_join)
        {
            igmp_join_common(igmp_interface, igmp_group);
        }
        else
        {
            igmp_leave_common(igmp_interface, igmp_group);
        }
    }
}


//
// Handle an IGMP leave
//
static void handle_igmp_v2_leave(
    igmp_interface_t *          igmp_interface,
    const uint8_t *             ip_src,
    const uint8_t *             igmp_buffer,
    unsigned int                igmp_len)
{
    mcb_igmp_t *                igmp = (mcb_igmp_t *) igmp_buffer;
    igmp_group_t *              igmp_group;
    char                        src_addr_str[INET_ADDRSTRLEN] = {0};
    char                        group_addr_str[INET_ADDRSTRLEN] = {0};

    // Confirm the packet is large enough to contain the leave
    if (igmp_len < sizeof(mcb_igmp_t))
    {
        igmp_log(igmp_interface, ip_src, "Packet too short to contain an IGMP leave");
        return;
    }

    // Find the group
    igmp_group = igmp_interface_find_group(igmp_interface, igmp->group);
    if (igmp_group == NULL)
    {
        return;
    }

    // Debug logging
    if (debug_level >= 3)
    {
        inet_ntop(AF_INET, ip_src, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET, igmp->group, group_addr_str, sizeof(group_addr_str));
        logger("IGMP(%s) [%s]: received v2 leave [group %s]\n", igmp_interface->name, src_addr_str, group_addr_str);
    }

    igmp_leave_common(igmp_interface, igmp_group);
}


//
// Process an incoming packet
//
static void igmp_receive(
    void *                      arg)
{
    igmp_interface_t *          igmp_interface = arg;
    struct pcap_pkthdr          pkthdr;
    const unsigned char *       packet;
    unsigned int                packet_len;
    const mcb_ethernet_t *      eth;
    const mcb_ip4_t *           ip;
    const mcb_ip4_ra_opt_t *    ip_ra;
    const mcb_igmp_header_t *   igmp_header;
    unsigned int                ip_header_len;
    unsigned int                ip_total_len;
    uint16_t                    calculated_csum;

    // Read the packet
    packet = pcap_next(igmp_interface->pcap, &pkthdr);
    if (packet == NULL)
    {
        return;
    }
    packet_len = pkthdr.caplen;

    // Confirm the header is large enough to contain ethernet and IPv4 headers
    if (packet_len < sizeof(mcb_ethernet_t) + sizeof(mcb_ip4_t))
    {
        igmp_log(igmp_interface, NULL, "Packet too short to contain an IPv4 header");
        return;
    }

    // Parse the ethernet header
    eth = (mcb_ethernet_t *) packet;
    if (ntohs(eth->type) != MCB_ETHERNET_TYPE_IP4)
    {
        igmp_log(igmp_interface, NULL, "Packet is not an IPv4 packet");
        return;
    }

    // Consume the ethernet header
    packet += sizeof(mcb_ethernet_t);
    packet_len -= sizeof(mcb_ethernet_t);

    // Parse the IPv4 header
    ip = (mcb_ip4_t *) packet;

    // Ignore my own packets
    if (MCB_IP4_ADDR_CMP(ip->src, igmp_interface->if_addr) == 0)
    {
        return;
    }

    // Check the header length
    ip_header_len = ip->header_len << 2;
    if (ip_header_len > packet_len)
    {
        igmp_log(igmp_interface, NULL, "IP header overrun");
        return;
    }

    // Verify the IP checksum
    calculated_csum = inet_csum((uint16_t *) ip, ip_header_len);
    if (calculated_csum != 0)
    {
        igmp_log(igmp_interface, ip->src, "IP checksum error");
        return;
    }

    // Check the total length
    ip_total_len = ntohs(ip->total_len);
    if (ip_total_len > packet_len)
    {
        igmp_log(igmp_interface, ip->src, "IP packet overrun");
        return;
    }
    packet_len = ip_total_len;

    // Confirm the protocol type
    if (ip->protocol != MCB_IP4_PROTOCOL_IGMP)
    {
        igmp_log(igmp_interface, ip->src, "Packet is not an IGMP packet");
        return;
    }

    // Confirm the header is large enough to contain the Router Alert option
    if (ip_header_len < sizeof(mcb_ip4_t) + sizeof(mcb_ip4_ra_opt_t))
    {
        igmp_log(igmp_interface, ip->src, "IP header too short to contain a Router Alert option");
        return;
    }

    // Confirm the Router Alert option
    ip_ra = (mcb_ip4_ra_opt_t *) (packet + sizeof(mcb_ip4_t));
    if (ip_ra->type != MCB_IP4_OPT_RA || ip_ra->length != 4)
    {
        igmp_log(igmp_interface, ip->src, "Packet does not contain a Router Alert option");
        return;
    }

    // Consume the IP header (includes the Router Alert option)
    packet += ip_header_len;
    packet_len -= ip_header_len;

    // Confirm the packet is large enough to contain the minimum IGMP header
    if (packet_len < sizeof(mcb_igmp_header_t))
    {
        igmp_log(igmp_interface, ip->src, "Packet too short to contain an IGMP header");
        return;
    }

    // Verify the IGMP checksum
    calculated_csum = inet_csum((uint16_t *) packet, packet_len);
    if (calculated_csum != 0)
    {
        igmp_log(igmp_interface, ip->src, "IGMP checksum error");
        return;
    }

    // Process the IGMP packet
    igmp_header = (mcb_igmp_header_t *) packet;
    switch (igmp_header->type)
    {
        case MCB_IGMP_QUERY:
            handle_igmp_query(igmp_interface, ip->src, packet, packet_len);
            break;

        case MCB_IGMP_V1_REPORT:
            handle_igmp_v1_report(igmp_interface, ip->src, packet, packet_len);
            break;

        case MCB_IGMP_V2_REPORT:
            handle_igmp_v2_report(igmp_interface, ip->src, packet, packet_len);
            break;

        case MCB_IGMP_V2_LEAVE:
            handle_igmp_v2_leave(igmp_interface, ip->src, packet, packet_len);
            break;

        case MCB_IGMP_V3_REPORT:
            handle_igmp_v3_report(igmp_interface, ip->src, packet, packet_len);
            break;

        case MCB_IGMP_MRD_SOLICITATION:
            handle_igmp_mrd_solicitation(igmp_interface, ip->src);
            break;

        case MCB_IGMP_MRD_ADVERTISEMENT:
        case MCB_IGMP_MRD_TERMINATION:
            // Ignored
            break;

        default:
            igmp_log(igmp_interface, ip->src, "Unknown IGMP type received");
            break;
    }
}


// Pcap
void igmp_pcap_create(
    igmp_interface_t *          igmp_interface)
{
    pcap_t *                    pcap;
    struct bpf_program          program;

    int                         r;
    int                         fd;
    char                        errbuf[PCAP_ERRBUF_SIZE];

    // Create the pcap session
    pcap = pcap_create(igmp_interface->name, errbuf);
    if (pcap == NULL)
    {
        fatal("pcap_create for interface %s failed: %s\n", igmp_interface->name, errbuf);
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
    r = pcap_compile(pcap, &program, IGMP_FILTER, 1, PCAP_NETMASK_UNKNOWN);
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
        fatal("pcap_get_selectable_fd for IGMP interface %s failed: %s\n", igmp_interface->name, pcap_geterr(pcap));
    }
    evm_add_socket(igmp_evm, fd, igmp_receive, igmp_interface);

    // Store the pcap session
    igmp_interface->pcap = pcap;
}


//
// Register a bridge interface for IGMP monitoring
//
void igmp_register_interface(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    igmp_interface_t *          igmp_interface;
    igmp_group_t *              igmp_group;
    unsigned int                interface_index;
    unsigned int                group_index;

    // Is the interface already in the igmp interface list?
    for (interface_index = 0; interface_index < igmp_interface_list_count; interface_index += 1)
    {
        igmp_interface = &igmp_interface_list[interface_index];

        if (bridge_interface->if_index == igmp_interface->if_index)
        {
            break;
        }
    }

    // If the interface wasn't found, add it
    if (interface_index >= igmp_interface_list_count)
    {
        // Do we need to (re)allocate the igmp interface list?
        if (interface_index >= igmp_interface_list_allocated)
        {
            // Determine the new allocation size
            if (igmp_interface_list_allocated == 0)
            {
                igmp_interface_list_allocated = 2;
            }
            else
            {
                igmp_interface_list_allocated *= 2;
            }

            igmp_interface_list = realloc(igmp_interface_list, igmp_interface_list_allocated * sizeof(igmp_interface_t));
            if (igmp_interface_list == NULL)
            {
                fatal("Cannot allocate memory for igmp interface list: %s\n", strerror(errno));
            }
        }

        // Add the new igmp interface to the list
        igmp_interface = &igmp_interface_list[interface_index];
        igmp_interface_list_count += 1;

        // Initialize the new igmp interface
        memset(igmp_interface, 0, sizeof(*igmp_interface));
        igmp_interface->name = bridge_interface->name;
        igmp_interface->if_index = bridge_interface->if_index;
        MCB_ETH_ADDR_CPY(igmp_interface->if_mac_addr, bridge_interface->mac_addr);
        MCB_IP4_ADDR_CPY(igmp_interface->if_addr, &bridge_interface->ipv4_addr);
    }

    // Is the group already in the list for this igmp interface?
    for (group_index = 0; group_index < igmp_interface->group_list_count; group_index += 1)
    {
        igmp_group = &igmp_interface->group_list[group_index];
        if (MCB_IP4_ADDR_CMP(igmp_group->mcast_addr, &bridge->dst_addr.sin.sin_addr) == 0)
        {
            break;
        }
    }

    // If the group wasn't found, add it
    if (group_index >= igmp_interface->group_list_count)
    {
        // Do we need to (re)allocate the group list?
        if (group_index >= igmp_interface->group_list_allocated)
        {
            // Determine the new allocation size
            if (igmp_interface->group_list_allocated == 0)
            {
                igmp_interface->group_list_allocated = 1;
            }
            else
            {
                igmp_interface->group_list_allocated *= 2;
            }

            igmp_interface->group_list = realloc(igmp_interface->group_list, igmp_interface->group_list_allocated * sizeof(igmp_group_t));
            if (igmp_interface->group_list == NULL)
            {
                fatal("Cannot allocate memory for igmp group list: %s\n", strerror(errno));
            }
        }

        // Add a new igmp group to the igmp interface's list
        igmp_group = &igmp_interface->group_list[group_index];
        igmp_interface->group_list_count += 1;

        // Initialize the new group
        memset(igmp_group, 0, sizeof(*igmp_group));
        // NB: igmp->igmp_interface will be set after the group list is finalized
        MCB_IP4_ADDR_CPY(igmp_group->mcast_addr, &bridge->dst_addr.sin.sin_addr.s_addr);
    }

    // Do we need to (re)allocate the list of bridge interfaces for this group?
    if (igmp_group->bridge_interface_list_count >= igmp_group->bridge_interface_list_allocated)
    {
        // Determine the new allocation size
        if (igmp_group->bridge_interface_list_allocated == 0)
        {
            igmp_group->bridge_interface_list_allocated = 1;
        }
        else
        {
            igmp_group->bridge_interface_list_allocated *= 2;
        }

        igmp_group->bridge_interface_list = realloc(igmp_group->bridge_interface_list, igmp_group->bridge_interface_list_allocated * sizeof(bridge_interface_t *));
        if (igmp_group->bridge_interface_list == NULL)
        {
            fatal("Cannot allocate memory for igmp group list: %s\n", strerror(errno));
        }
    }

    // Add the bridge interface to the list of interfaces for this group
    igmp_group->bridge_interface_list[igmp_group->bridge_interface_list_count] = bridge_interface;
    igmp_group->bridge_interface_list_count += 1;
}


//
// IGMP thread
//
__attribute__ ((noreturn))
static void * igmp_thread(
    __attribute__ ((unused))
    void *                      arg)
{
    // Run the event loop
    evm_loop(igmp_evm);
}


//
// Dump the IGMP configuration
//
static void igmp_dump_config()
{
    igmp_interface_t *          igmp_interface;
    igmp_group_t *              igmp_group;
    unsigned int                interface_index;
    unsigned int                group_index;
    char                        addr_str[INET_ADDRSTRLEN];

    printf("IGMP:\n");
    printf("  Querier Mode: ");
    switch(igmp_querier_mode)
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

    for (interface_index = 0; interface_index < igmp_interface_list_count; interface_index += 1)
    {
        igmp_interface = &igmp_interface_list[interface_index];

        printf("  Interface: %s\n", igmp_interface->name);
        printf("    if index: %d\n", igmp_interface->if_index);
        printf("    hw-addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        igmp_interface->if_mac_addr[0], igmp_interface->if_mac_addr[1], igmp_interface->if_mac_addr[2],
                        igmp_interface->if_mac_addr[3], igmp_interface->if_mac_addr[4], igmp_interface->if_mac_addr[5]);
        printf("    address: %s\n", inet_ntop(AF_INET, igmp_interface->if_addr, addr_str, sizeof(addr_str)));
        printf("    groups:\n");
        for (group_index = 0; group_index < igmp_interface->group_list_count; group_index += 1)
        {
            igmp_group = &igmp_interface->group_list[group_index];
            printf("      %s\n", inet_ntop(AF_INET, igmp_group->mcast_addr, addr_str, sizeof(addr_str)));
        }
    }
}


//
// Initialize the IGMP infrastructure
//
void initialize_igmp(
    unsigned int                dump_config)
{
    igmp_interface_t *          igmp_interface;
    igmp_group_t *              igmp_group;
    unsigned int                interface_index;
    unsigned int                group_index;
    unsigned int                total_groups = 0;
    uint32_t                    haddr;

    // Nothing to do if there are no interfaces
    if (igmp_interface_list_count < 1)
    {
        return;
    }

    // Dump the IGMP configuration
    if (dump_config)
    {
        igmp_dump_config();
    }

    // Initialize special addresses
    haddr = htonl(MCB_IP4_ALL_SYSTEMS);
    MCB_IP4_ADDR_CPY(allhosts_addr, &haddr);
    haddr = htonl(MCB_IP4_ALL_SNOOPERS);
    MCB_IP4_ADDR_CPY(allsnoopers_addr, &haddr);

    // Finalize the interfaces and groups
    for (interface_index = 0; interface_index < igmp_interface_list_count; interface_index += 1)
    {
        igmp_interface = &igmp_interface_list[interface_index];

        // Set the fixed group limit
        igmp_interface->group_list_fixed_limit = igmp_interface->group_list_count;

        // Adjust the group list size to allow for non configured groups
        igmp_interface->group_list_allocated = igmp_interface->group_list_count + non_configured_groups;
        igmp_interface->group_list = realloc(igmp_interface->group_list, igmp_interface->group_list_allocated * sizeof(igmp_group_t));
        if (igmp_interface->group_list == NULL)
        {
            fatal("Cannot allocate memory for igmp group list: %s\n", strerror(errno));
        }

        // Initialize the new groups
        memset(&igmp_interface->group_list[igmp_interface->group_list_count], 0,
            (igmp_interface->group_list_allocated - igmp_interface->group_list_count) * sizeof(igmp_group_t));

        // Now that all the (re)allocation is done, set the interface pointers in the groups
        for (group_index = 0; group_index < igmp_interface->group_list_count; group_index += 1)
        {
            igmp_group = &igmp_interface->group_list[group_index];
            igmp_group->igmp_interface = igmp_interface;
        }

        total_groups += igmp_interface->group_list_allocated;
    }

    // Create the event manager
    // NB: The number of timers is a theoretical maximum. In actual use, the number of timers
    //     is expected to be significantly less than half of this number.
    igmp_evm = evm_create(igmp_interface_list_count, igmp_interface_list_count * 2 + total_groups * 2);
    if (igmp_evm == NULL)
    {
        fatal("Cannot create event manager\n");
    }

    // Create the pcap instances and register them with the event manager
    for (interface_index = 0; interface_index < igmp_interface_list_count; interface_index += 1)
    {
        igmp_interface = &igmp_interface_list[interface_index];
        igmp_pcap_create(igmp_interface);
    }
}


//
// Start the IGMP thread
//
void start_igmp(void)
{
    igmp_interface_t *          igmp_interface;
    unsigned int                interface_index;
    pthread_t                   thread_id;
    long                        seed;
    int                         r;

    // Nothing to do if there are no interfaces
    if (igmp_interface_list_count < 1)
    {
        return;
    }

    // Seed the random number generator
    seed = time(NULL) ^ getpid();
    random_state[0] = 0x330e;
    random_state[1] = seed;
    random_state[2] = seed >> 16;

    // Set up the querier for each interface
    for (interface_index = 0; interface_index < igmp_interface_list_count; interface_index += 1)
    {
        igmp_interface = &igmp_interface_list[interface_index];

        // Build the multicast router advertisement packet
        igmp_build_mrd_advertisement_packet(igmp_interface);

        // Send the first multicast router advertisement (no jitter)
        igmp_interface->mrd_initial_advertisements_remaining = MCB_MRD_INITIAL_COUNT - 1;
        igmp_send_mrd_advertisement(igmp_interface);

        // Build the query packets
        igmp_build_query_packets(igmp_interface);

        // Is quick querier mode enabled?
        if (igmp_querier_mode == QUERIER_MODE_QUICK)
        {
            igmp_activate_querier_mode(igmp_interface);
        }
        else
        {
            // Set default querier values
            igmp_interface->querier_robustness = MCB_IGMP_ROBUSTNESS;
            igmp_interface->querier_interval_sec = MCB_IGMP_QUERY_INTERVAL;
            igmp_interface->querier_response_interval_tenths = MCB_IGMP_RESPONSE_INTERVAL;
            igmp_interface->querier_lastmbr_interval_tenths = MCB_IGMP_LASTMBR_INTERVAL;

            // Set the querier address to all ones allowing anyone to win an election
            MCB_IP4_ADDR_SET(igmp_interface->querier_addr, 0xff);

            // Is querier mode enabled?
            if (igmp_querier_mode)
            {
                // Set a timer to activate as a querier (125.5 seconds)
                evm_add_timer(igmp_evm, 125500, igmp_querier_timeout, igmp_interface);
            }
        }
    }

    // Start the thread
    r = pthread_create(&thread_id, NULL, &igmp_thread, NULL);
    if (r != 0)
    {
        fatal("cannot create IGMP thread: %s\n", strerror(errno));
    }
}
