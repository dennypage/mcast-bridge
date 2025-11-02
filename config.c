
//
// Copyright (c) 2024-2025, Denny Page
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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#if defined(__FreeBSD__) || defined (__APPLE__)
# define USE_SOCKADDR_DL
# include <net/if_dl.h>
#else
# include <netpacket/packet.h>
#endif

#include "common.h"


// Limits for internal configuration arrays
#define MAX_INPUT_LINE                  16384
#define MAX_LIST_ARRAY                  1024
#define MAX_INTERFACES                  64

// Keys for configuration sections
#define KEY_IPV4_ADDRESS                "ipv4-address"
#define KEY_IPV6_ADDRESS                "ipv6-address"
#define KEY_INBOUND_INTERFACES          "inbound-interfaces"
#define KEY_OUTBOUND_INTERFACES         "outbound-interfaces"
#define KEY_STATIC_INBOUND_INTERFACES   "static-inbound-interfaces"
#define KEY_STATIC_OUTBOUND_INTERFACES  "static-outbound-interfaces"

// Determine if an address is an IPv4 Link Local address (169.254.0.0/16)
#define MCB_ADDR_IS_IPV4_LL(addr)       ((ntohl(addr) & 0xffff0000) == 0xa9fe0000)

// Determine if an address is an IPv6 Link Local address (FE80::/10)
#define MCB_ADDR_IS_IPV6_LL(addr)       ((addr[0] == 0xfe) && (addr[1] & 0xc0) == 0x80)

// Determine if an address is an IPv6 Unique Local address (FC00::/7)
#define MCB_ADDR_IS_IPV6_ULA(addr)      ((addr[0] & 0xfe) == 0xfc)

// Determine if an IPv4 multicast address is in the link local space (224.0.0.0/24)
#define MCB_ADDR_IS_IPV4_MC_LOCAL(addr) (((in_addr_t)(addr) & 0xffffff00) == 0xe0000000)

// Determine if an IPv6 multicast address is in the link local space (FF02::/16)
#define MCB_ADDR_IS_IPV6_MC_LOCAL(addr) ((addr[0] == 0xff) && (addr[1] == 0x02))


// Draft interface structure
typedef struct draft_interface
{
    char *                      name;
    unsigned int                if_index;

    interface_config_type_t     inbound_configuration;
    interface_config_type_t     outbound_configuration;

    unsigned int                has_ipv4_addr;
    unsigned int                has_ipv6_addr;
    unsigned int                has_ipv6_addr_ll;

    struct in_addr              ipv4_addr;
    struct in6_addr             ipv6_addr;
    struct in6_addr             ipv6_addr_ll;
    uint8_t                     mac_addr[6];
} draft_interface_t;

// Draft bridge structure
typedef struct draft_bridge
{
    unsigned short              port;
    unsigned int                has_ipv4_mcast_addr;
    unsigned int                has_ipv6_mcast_addr;

    struct in_addr              ipv4_mcast_addr;
    struct in6_addr             ipv6_mcast_addr;

    draft_interface_t           interfaces[MAX_INTERFACES];
    unsigned int                interface_count;

    unsigned int                inbound_ipv4_count;
    unsigned int                outbound_ipv4_count;
    unsigned int                inbound_ipv6_count;
    unsigned int                outbound_ipv6_count;

    draft_interface_t *         last_inbound_ipv4_interface;
    draft_interface_t *         last_inbound_ipv6_interface;
    draft_interface_t *         last_outbound_ipv4_interface;
    draft_interface_t *         last_outbound_ipv6_interface;
} draft_bridge_t;


// OS ifaddrs list
static struct ifaddrs *         ifaddr_list;

// Current configuration line
static unsigned int             config_lineno = 0;

// Bridge list (finalized configuration)
bridge_instance_t *             bridge_list = NULL;
unsigned int                    bridge_list_allocated = 0;
unsigned int                    bridge_list_count = 0;



//
// Add an interface to the draft bridge
//
static draft_interface_t * add_draft_interface(
    draft_bridge_t *            draft_bridge,
    char *                      name)
{
    draft_interface_t *         interface;
    unsigned int                if_index;
    unsigned int                interface_index;
    struct ifaddrs *            ifaddr_ptr;
    struct sockaddr *           sa;
    struct sockaddr_in *        sin;
    struct sockaddr_in6 *       sin6;

    // Get the interface index
    if_index = if_nametoindex(name);
    if (if_index == 0)
    {
        fatal("%s line %u: Interface \"%s\" does not exist\n", config_filename, config_lineno, name);
    }

    // Is the interface already in the list?
    for (interface_index = 0; interface_index < draft_bridge->interface_count; interface_index += 1)
    {
        interface = &draft_bridge->interfaces[interface_index];

        if (interface->if_index == if_index)
        {
            return interface;
        }
    }

    // Safety check
    if (draft_bridge->interface_count >= MAX_INTERFACES)
    {
        fatal("%s line %u: Maximun number of interfaces (%u) exceeded\n", config_filename, config_lineno, MAX_INTERFACES);
    }

    // Add a new interface to the list
    interface = &draft_bridge->interfaces[draft_bridge->interface_count];
    draft_bridge->interface_count += 1;

    // Initialize the interface
    memset(interface, 0, sizeof(*interface));
    interface->if_index = if_index;
    interface->name = strdup(name);
    if (interface->name == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // Search the ifaddr list for the interface
    for (ifaddr_ptr = ifaddr_list; ifaddr_ptr != NULL; ifaddr_ptr = ifaddr_ptr->ifa_next)
    {
        if (strcmp(ifaddr_ptr->ifa_name, name) == 0)
        {
            sa = ifaddr_ptr->ifa_addr;
            if (sa)
            {
                // Confirm the interface is up and supports multicast
                if ((ifaddr_ptr->ifa_flags & IFF_UP) == 0)
                {
                    fatal("%s line %u: Interface \"%s\" is not up\n", config_filename, config_lineno, interface->name);
                }
                if ((ifaddr_ptr->ifa_flags & IFF_MULTICAST) == 0)
                {
                    fatal("%s line %u: Interface \"%s\" does not support multicast\n", config_filename, config_lineno, interface->name);
                }

                // Save the MAC address
#if defined(USE_SOCKADDR_DL)
                if (sa->sa_family == AF_LINK)
                {
                    struct sockaddr_dl * sdl = (struct sockaddr_dl *) sa;
                    uint8_t * mac = (uint8_t *) LLADDR(sdl);
                    memcpy(interface->mac_addr, mac, sizeof(interface->mac_addr));
                    continue;
                }
#else
                if (sa->sa_family == AF_PACKET)
                {
                    struct sockaddr_ll * sll = (struct sockaddr_ll *) sa;
                    uint8_t * mac = (uint8_t *) sll->sll_addr;
                    memcpy(interface->mac_addr, mac, sizeof(interface->mac_addr));
                    continue;
                }
#endif

                // Check the IPv4 and IPv6 addresses
                if (sa->sa_family == AF_INET)
                {
                    sin = (struct sockaddr_in *) sa;
                    if (interface->has_ipv4_addr)
                    {
                        // Favor global addresses over link-local ones
                        if (MCB_ADDR_IS_IPV4_LL(sin->sin_addr.s_addr))
                        {
                            continue;
                        }
                    }

                    interface->has_ipv4_addr = 1;
                    memcpy(&interface->ipv4_addr, &sin->sin_addr, sizeof(interface->ipv4_addr));
                }
                else if (sa->sa_family == AF_INET6)
                {
                    sin6 = (struct sockaddr_in6 *) sa;

                    // Save the link-local address
                    if (interface->has_ipv6_addr_ll == 0 && MCB_ADDR_IS_IPV6_LL(sin6->sin6_addr.s6_addr))
                    {
                        interface->has_ipv6_addr_ll = 1;
                        memcpy(&interface->ipv6_addr_ll, &sin6->sin6_addr, sizeof(interface->ipv6_addr));
                    }

                    // Save the general use address
                    if (interface->has_ipv6_addr)
                    {
                        // Favor global addresses over link-local or unique-local
                        if (MCB_ADDR_IS_IPV6_LL(sin6->sin6_addr.s6_addr) || MCB_ADDR_IS_IPV6_ULA(sin6->sin6_addr.s6_addr))
                        {
                            continue;
                        }
                    }

                    interface->has_ipv6_addr = 1;
                    memcpy(&interface->ipv6_addr, &sin6->sin6_addr, sizeof(interface->ipv6_addr));
                }
            }
        }
    }

    // Ensure the interface has at least one IP address
    if (interface->has_ipv4_addr == 0 && interface->has_ipv6_addr == 0)
    {
        fatal("%s line %u: Interface \"%s\" does not have an IP address\n", config_filename, config_lineno, name);
    }

    return interface;
}


//
// Validate a draft bridge
//
static void validate_draft_bridge(
    draft_bridge_t *            draft_bridge)
{
    draft_interface_t *         last_inbound_interface = NULL;
    draft_interface_t *         last_outbound_interface = NULL;
    unsigned int                inbound_count = 0;
    unsigned int                outbound_count = 0;
    unsigned int                interface_index;

    // Ensure the bridge has at least one multicast group address
    if (draft_bridge->has_ipv4_mcast_addr == 0 && draft_bridge->has_ipv6_mcast_addr == 0)
    {
        fatal("Bridge %u does not have a multicast group address\n", draft_bridge->port);
    }

    // Count the number of inbound and outbound interfaces
    for (interface_index = 0; interface_index < draft_bridge->interface_count; interface_index += 1)
    {
        if (draft_bridge->interfaces[interface_index].inbound_configuration != INTERFACE_CONFIG_NONE)
        {
            inbound_count += 1;
            last_inbound_interface = &draft_bridge->interfaces[interface_index];
            if (last_inbound_interface->has_ipv4_addr)
            {
                draft_bridge->inbound_ipv4_count += 1;
                draft_bridge->last_inbound_ipv4_interface = last_inbound_interface;
            }
            if (last_inbound_interface->has_ipv6_addr)
            {
                draft_bridge->inbound_ipv6_count += 1;
                draft_bridge->last_inbound_ipv6_interface = last_inbound_interface;
            }
        }

        if (draft_bridge->interfaces[interface_index].outbound_configuration != INTERFACE_CONFIG_NONE)
        {
            outbound_count += 1;
            last_outbound_interface = &draft_bridge->interfaces[interface_index];
            if (last_outbound_interface->has_ipv4_addr)
            {
                draft_bridge->outbound_ipv4_count += 1;
                draft_bridge->last_outbound_ipv4_interface = last_outbound_interface;
            }
            if (last_outbound_interface->has_ipv6_addr)
            {
                draft_bridge->outbound_ipv6_count += 1;
                draft_bridge->last_outbound_ipv6_interface = last_outbound_interface;
            }
        }
    }

    // Ensure the bridge has at least one inbound and outbound interface
    if (inbound_count == 0)
    {
        fatal("Bridge %u does not have any inbound interfaces\n", draft_bridge->port);
    }
    if (outbound_count == 0)
    {
        fatal("Bridge %u does not have any outbound interfaces\n", draft_bridge->port);
    }

    // If there is only one inbound interface, ensure it not listed as an outbound interface
    if (inbound_count == 1)
    {
        if (last_inbound_interface->outbound_configuration != INTERFACE_CONFIG_NONE)
        {
            fatal("Bridge %u has a single inbound interface (%s) which is also declared as an outbound interface\n",
            draft_bridge->port, last_inbound_interface->name);
        }
    }

    // If there is only one outbound interface, ensure it not listed as an inbound interface
    if (outbound_count == 1)
    {
        if (last_outbound_interface->inbound_configuration != INTERFACE_CONFIG_NONE)
        {
            fatal("Bridge %u has a single outbound interface (%s) which is also declared as an inbound interface\n",
            draft_bridge->port, last_outbound_interface->name);
        }
    }

    // If using IPv4, ensure we have at least one unique inbound and outbound interface with an IPv4 address
    if (draft_bridge->has_ipv4_mcast_addr)
    {
        if (draft_bridge->inbound_ipv4_count == 0)
        {
            fatal("Bridge %u has an IPv4 multicast group address, but does not have an IPv4 enabled inbound interface\n", draft_bridge->port);
        }
        if (draft_bridge->outbound_ipv4_count == 0)
        {
            fatal("Bridge %u has an IPv4 multicast group address, but does not have an IPv4 enabled outbound interface\n", draft_bridge->port);
        }
        if (draft_bridge->inbound_ipv4_count == 1 && draft_bridge->outbound_ipv4_count == 1)
        {
            if (draft_bridge->last_inbound_ipv4_interface == draft_bridge->last_outbound_ipv4_interface)
            {
                fatal("Bridge %u has an IPv4 multicast group address, but has only one IPv4 enabled interface (%s)\n",
                    draft_bridge->port, draft_bridge->last_inbound_ipv4_interface->name);
            }
        }
    }

    // If using IPv6, ensure we have at least one unique inbound and outbound interface with an IPv6 address
    if (draft_bridge->has_ipv6_mcast_addr)
    {
        if (draft_bridge->inbound_ipv6_count == 0)
        {
            fatal("Bridge %u has an IPv6 multicast group address, but does not have an IPv6 enabled inbound interface\n", draft_bridge->port);
        }
        if (draft_bridge->outbound_ipv6_count == 0)
        {
            fatal("Bridge %u has an IPv6 multicast group address, but does not have an IPv6 enabled outbound interface\n", draft_bridge->port);
        }
        if (draft_bridge->inbound_ipv6_count == 1 && draft_bridge->outbound_ipv6_count == 1)
        {
            if (draft_bridge->last_inbound_ipv6_interface == draft_bridge->last_outbound_ipv6_interface)
            {
                fatal("Bridge %u has an IPv6 multicast group address, but has only one IPv6 enabled interface (%s)\n",
                    draft_bridge->port, draft_bridge->last_inbound_ipv6_interface->name);
            }
        }
    }
}


//
// Add an IPv4 or IPv6 bridge based on a draft bridge
//
static void add_bridge(
    struct draft_bridge *       draft_bridge,
    unsigned int                family)
{
    unsigned int                bridge_index;
    bridge_instance_t *         bridge;
    bridge_interface_t *        interface;
    draft_interface_t *         draft_interface;
    unsigned int                draft_interface_index;
    unsigned int                outbound_index;
    unsigned int                inbound_index;

    // Sanity checks
    if (family == AF_INET)
    {
        if (draft_bridge->inbound_ipv4_count == 0 || draft_bridge->outbound_ipv4_count == 0)
        {
            return;
        }
    }
    else
    {
        if (draft_bridge->inbound_ipv6_count == 0 || draft_bridge->outbound_ipv6_count == 0)
        {
            return;
        }
    }

    // Do we need to (re)allocate the bridge list?
    if (bridge_list_count >= bridge_list_allocated)
    {
        // Determine the new allocation size
        if (bridge_list_allocated == 0)
        {
            bridge_list_allocated = 1;
        }
        else
        {
            bridge_list_allocated *= 2;
        }

        bridge_list = realloc(bridge_list, bridge_list_allocated * sizeof(bridge_instance_t));
        if (bridge_list == NULL)
        {
            fatal("Cannot allocate memory for bridge list: %s\n", strerror(errno));
        }
    }

    // Add the bridge
    bridge_index = bridge_list_count;
    bridge_list_count += 1;

    // Initialize the bridge
    bridge = &bridge_list[bridge_index];
    memset(bridge, 0, sizeof(*bridge));
    bridge->family = family;
    bridge->port = draft_bridge->port;
    if (family == AF_INET)
    {
        bridge->dst_addr.sin.sin_family = family;
        bridge->dst_addr.sin.sin_port = htons(draft_bridge->port);
        memcpy(&bridge->dst_addr.sin.sin_addr, &draft_bridge->ipv4_mcast_addr, sizeof(struct in_addr));
        bridge->dst_addr_len = sizeof(struct sockaddr_in);
    }
    else
    {
        bridge->dst_addr.sin6.sin6_family = AF_INET6;
        bridge->dst_addr.sin6.sin6_port = htons(draft_bridge->port);
        memcpy(&bridge->dst_addr.sin6.sin6_addr, &draft_bridge->ipv6_mcast_addr, sizeof(struct in6_addr));
        bridge->dst_addr_len = sizeof(struct sockaddr_in6);
    }

    // Allocate the interface list
    bridge->interface_list = calloc(draft_bridge->interface_count, sizeof(bridge_interface_t));
    if (bridge->interface_list == NULL)
    {
        fatal("Failed to allocate interface list for %s bridge %u\n", family == AF_INET ? "IPv4" : "IPv6", draft_bridge->port);
    }

    // Add the interfaces
    for (draft_interface_index = 0; draft_interface_index < draft_bridge->interface_count; draft_interface_index += 1)
    {
        draft_interface = &draft_bridge->interfaces[draft_interface_index];

        // Skip the interface if it does not have an appropriate address
        if (family == AF_INET)
        {
            if (draft_interface->has_ipv4_addr == 0)
            {
                continue;
            }
        }
        else
        {
            if (draft_interface->has_ipv6_addr == 0)
            {
                continue;
            }
        }

        // Assign the interface
        interface = &bridge->interface_list[bridge->interface_count];
        bridge->interface_count += 1;

        // Assign the interface values
        interface->bridge_index = bridge_index;
        interface->inbound_configuration = draft_interface->inbound_configuration;
        interface->outbound_configuration = draft_interface->outbound_configuration;
        interface->name = draft_interface->name;
        interface->if_index = draft_interface->if_index;
        memcpy(interface->mac_addr, draft_interface->mac_addr, sizeof(interface->mac_addr));
        if (family == AF_INET)
        {
            memcpy(&interface->ipv4_addr, &draft_interface->ipv4_addr, sizeof(struct in_addr));
        }
        else
        {
            memcpy(&interface->ipv6_addr_ll, &draft_interface->ipv6_addr_ll, sizeof(struct in6_addr));
            memcpy(&interface->ipv6_addr, &draft_interface->ipv6_addr, sizeof(struct in6_addr));
        }
    }

    // If an outbound interface is static, associated dynamic inbound interfaces are forced to static
    for (outbound_index = 0; outbound_index < bridge->interface_count; outbound_index += 1)
    {
        if (bridge->interface_list[outbound_index].outbound_configuration == INTERFACE_CONFIG_STATIC)
        {
            for (inbound_index = 0; inbound_index < bridge->interface_count; inbound_index += 1)
            {
                if (inbound_index == outbound_index)
                {
                    continue;
                }
                if (bridge->interface_list[inbound_index].inbound_configuration == INTERFACE_CONFIG_DYNAMIC)
                {
                    bridge->interface_list[inbound_index].inbound_configuration = INTERFACE_CONFIG_FORCED;
                }
            }
        }
    }
}


//
// Trim (skip) leading whitespace from a string
//
static char * trim_leading_whitespace(
    char *                      str)
{
    while (isspace(*str))
    {
        str += 1;
    }

    return (str);
}


//
// Trim trailing whitespace from a string
//
static void trim_trailing_whitespace(
    char *                      str)
{
    char *                      end;

    end = str + strlen(str) - 1;
    while (isspace(*end))
    {
        *end = 0;
        end -= 1;
    }
}


//
// Split a line into a key and value
//
static char * split_keyvalue(
    char *                      line)
{
    char *                      value;

    // Ensure it's actually an assignment
    value = strchr(line, '=');
    if (value == NULL)
    {
        fatal("%s line %u: Syntax error - missing assignment\n", config_filename, config_lineno);
    }
    *value = 0;

    // Trim the value and ensure it is not empty
    value = trim_leading_whitespace(value + 1);
    if (*value == 0)
    {
        fatal("%s line %u: Syntax error - missing value\n", config_filename, config_lineno);
    }

    // Trim the key
    trim_trailing_whitespace(line);

    return (value);
}


//
// Convert a comma separated list of strings into a sorted array
// NB: The array MUST be at least MAX_LIST_ARRAY in size
//
static unsigned int split_comma_list(
    char *                      str,
    char **                     array)
{
    unsigned int                index = 0;

    // Add the first element to the array
    array[0] = str;

    while (*str)
    {
        if (*str == ',')
        {
            if (index + 1 >= MAX_LIST_ARRAY)
            {
                fatal("%s line %u: Invalid list - elements exceed max allowed (%u)\n", config_filename, config_lineno, MAX_LIST_ARRAY);
            }

            // Terminate the current element
            *str = 0;
            trim_trailing_whitespace(str);

            // Ensure the current element is not empty
            if (array[index] == str)
            {
                fatal("%s line %u: Invalid list - empty element\n", config_filename, config_lineno);
            }

            // Insure the next element is not empty
            str = trim_leading_whitespace(str + 1);
            if (*str == 0)
            {
                fatal("%s line %u: Invalid list - empty element\n", config_filename, config_lineno);
            }

            // Add the new element to the array
            index += 1;
            array[index] = str;
        }
        else
        {
            str += 1;
        }
    }

    return (index + 1);
}


//
// Read a line from the config file
// NB: The buffer MUST be at least MAX_INPUT_LINE in size
//
static char * read_line(
    FILE *                      fp,
    char *                      buffer)
{
    char *                      line;

    while (fgets(buffer, MAX_INPUT_LINE, fp) != NULL)
    {
        config_lineno += 1;

        // Trim leading whitespace spaces
        line = trim_leading_whitespace(buffer);

        // Ignore empty and comment lines
        if (*line == 0 || *line == '#')
        {
            continue;
        }

        // Trim trailing whitespace
        trim_trailing_whitespace(line);
        return line;
    }

    return NULL;
}


//
// Read and process the config file
//
void read_config(void)
{
    FILE *                      fp;
    char                        buffer[MAX_INPUT_LINE];
    char *                      list_array[MAX_LIST_ARRAY];
    unsigned int                list_array_count;
    unsigned int                list_array_index;
    char *                      line;
    char *                      value;
    draft_bridge_t              draft_bridge;
    draft_interface_t *         draft_interface;
    unsigned long               lport;
    unsigned int                offset;
    int                         r;

    // Open the config file
    fp = fopen(config_filename, "r");
    if (fp == NULL)
    {
        fatal("Unable to open config file \"%s\"\n", config_filename);
    }

    // Get the ifaddrs list
    if (getifaddrs(&ifaddr_list) == -1)
    {
        fatal("getifaddrs failed: %s\n", strerror(errno));
    }

    // Process sections
    line = read_line(fp, buffer);
    while (line && line[0] == '[')
    {
        // Ignore leading whitespace
        line = trim_leading_whitespace(line + 1);

        // Ensure the section name (port number) is terminated
        offset = strlen(line) - 1;
        if (line[offset] != ']')
        {
            fatal("%s line %u: Syntax error\n", config_filename, config_lineno);
        }
        line[offset] = 0;

        // Ignore trailing whitespace
        trim_trailing_whitespace(line);

        // Insure the port number is valid
        lport = 0;
        if (strlen(line) && strspn(line, "0123456789") == strlen(line))
        {
            lport = strtoul(line, NULL, 10);
        }
        if (lport < 1 || lport > 65535)
        {
            fatal("%s line %u: Invalid port number\n", config_filename, config_lineno);
        }

        // Clear the draft bridge
        memset(&draft_bridge, 0, sizeof(draft_bridge));

        // Set the port
        draft_bridge.port = (unsigned short) lport;

        // Read the rest of the bridge section
        while ((line = read_line(fp, buffer)))
        {
            if (*line == '[')
            {
                break;
            }

            // Split the key/value pair
            value = split_keyvalue(line);

            if (strcmp(line, KEY_IPV4_ADDRESS) == 0)
            {
                // Store the multicast address
                r = inet_pton(AF_INET, value, &draft_bridge.ipv4_mcast_addr);
                if (r == 0)
                {
                    fatal("%s line %u: Invalid IPv4 address \"%s\"\n", config_filename, config_lineno, value);
                }
                if (!IN_MULTICAST(ntohl(draft_bridge.ipv4_mcast_addr.s_addr)))
                {
                    fatal("%s line %u: Invalid IPv4 multicast group address \"%s\"\n", config_filename, config_lineno, value);
                }
                if (MCB_ADDR_IS_IPV4_MC_LOCAL(ntohl(draft_bridge.ipv4_mcast_addr.s_addr)))
                {
                    fatal("%s line %u: Multicast group address \"%s\" is link local (224.0.0.0/8) and cannot be bridged\n", config_filename, config_lineno, value);
                }
                draft_bridge.has_ipv4_mcast_addr = 1;
            }
            else if (strcmp(line, KEY_IPV6_ADDRESS) == 0)
            {
                // Store the multicast address
                r = inet_pton(AF_INET6, value, &draft_bridge.ipv6_mcast_addr);
                if (r == 0)
                {
                    fatal("%s line %u: Invalid IPv6 address \"%s\"\n", config_filename, config_lineno, value);
                }
                if (!IN6_IS_ADDR_MULTICAST(&draft_bridge.ipv6_mcast_addr))
                {
                    fatal("%s line %u: Invalid IPv6 multicast group address \"%s\"\n", config_filename, config_lineno, value);
                }
                if (MCB_ADDR_IS_IPV6_MC_LOCAL(draft_bridge.ipv6_mcast_addr.s6_addr))
                {
                    fatal("%s line %u: Multicast group address \"%s\" is link local (ff02::/16) and cannot be bridged\n", config_filename, config_lineno, value);
                }
                draft_bridge.has_ipv6_mcast_addr = 1;
            }
            else if (strcmp(line, KEY_INBOUND_INTERFACES) == 0)
            {
                // Add the interfaces
                list_array_count = split_comma_list(value, list_array);
                if (list_array_count == 0)
                {
                    fatal("%s line %u: Syntax error - missing interface list\n", config_filename, config_lineno);
                }
                for (list_array_index = 0; list_array_index < list_array_count; list_array_index += 1)
                {
                    draft_interface = add_draft_interface(&draft_bridge, list_array[list_array_index]);
                    if (draft_interface->inbound_configuration != INTERFACE_CONFIG_STATIC)
                    {
                        draft_interface->inbound_configuration = INTERFACE_CONFIG_DYNAMIC;
                    }
                }
            }
            else if (strcmp(line, KEY_OUTBOUND_INTERFACES) == 0)
            {
                // Add the interfaces
                list_array_count = split_comma_list(value, list_array);
                if (list_array_count == 0)
                {
                    fatal("%s line %u: Syntax error - missing interface list\n", config_filename, config_lineno);
                }
                for (list_array_index = 0; list_array_index < list_array_count; list_array_index += 1)
                {
                    draft_interface = add_draft_interface(&draft_bridge,  list_array[list_array_index]);
                    if (draft_interface->outbound_configuration != INTERFACE_CONFIG_STATIC)
                    {
                        draft_interface->outbound_configuration = INTERFACE_CONFIG_DYNAMIC;
                    }
                }
            }
            else if (strcmp(line, KEY_STATIC_INBOUND_INTERFACES) == 0)
            {
                // Add the interfaces
                list_array_count = split_comma_list(value, list_array);
                if (list_array_count == 0)
                {
                    fatal("%s line %u: Syntax error - missing interface list\n", config_filename, config_lineno);
                }
                for (list_array_index = 0; list_array_index < list_array_count; list_array_index += 1)
                {
                    draft_interface = add_draft_interface(&draft_bridge, list_array[list_array_index]);
                    draft_interface->inbound_configuration = INTERFACE_CONFIG_STATIC;

                }
            }
            else if (strcmp(line, KEY_STATIC_OUTBOUND_INTERFACES) == 0)
            {
                // Add the interfaces
                list_array_count = split_comma_list(value, list_array);
                if (list_array_count == 0)
                {
                    fatal("%s line %u: Syntax error - missing interface list\n", config_filename, config_lineno);
                }
                for (list_array_index = 0; list_array_index < list_array_count; list_array_index += 1)
                {
                    draft_interface = add_draft_interface(&draft_bridge,  list_array[list_array_index]);
                    draft_interface->outbound_configuration = INTERFACE_CONFIG_STATIC;
                }
            }
            else
            {
                fatal("%s line %u: Unknown interface parameter \"%s\"\n", config_filename, config_lineno, line);
            }
        }

        // Validate the draft
        validate_draft_bridge(&draft_bridge);

        // Add an IPv4 bridge if configured
        if (draft_bridge.has_ipv4_mcast_addr && draft_bridge.inbound_ipv4_count && draft_bridge.outbound_ipv4_count)
        {
            add_bridge(&draft_bridge, AF_INET);
        }

        // Add an IPv6 bridge if configured
        if (draft_bridge.has_ipv6_mcast_addr && draft_bridge.inbound_ipv6_count && draft_bridge.outbound_ipv6_count)
        {
            add_bridge(&draft_bridge, AF_INET6);
        }
    }

    // Ensure we reached the end of the file
    if (line != NULL)
    {
        fatal("%s line %u: Syntax error\n", config_filename, config_lineno);
    }

    // Ensure we have at least one bridge
    if (bridge_list_count == 0)
    {
        fatal("%s line %u: No port bridges defined\n", config_filename, config_lineno);
    }

    // Clean up
    freeifaddrs(ifaddr_list);
    fclose(fp);
}


//
// Map an interface configuration type to a string
//
char * interface_config_type_to_string(
    interface_config_type_t  interface_config_type)
{
    switch (interface_config_type)
    {
        case INTERFACE_CONFIG_NONE:
            return "none";
        case INTERFACE_CONFIG_DYNAMIC:
            return "dynamic";
        case INTERFACE_CONFIG_STATIC:
            return "static";
        case INTERFACE_CONFIG_FORCED:
            return "forced";
        default:
            return "unknown";
    }
}


//
// Dump the finalized bridges
//
void dump_config(void)
{
    bridge_instance_t *         bridge;
    bridge_interface_t *        interface;
    unsigned int                bridge_index;
    unsigned int                interface_index;
    unsigned short              family;
    char                        addr_str[INET6_ADDRSTRLEN];

    // Print the bridges
    printf("Bridges:\n");
    for (bridge_index = 0; bridge_index < bridge_list_count; bridge_index++)
    {
        // Port mumber and IP type
        bridge = &bridge_list[bridge_index];
        family = bridge->family;

        // Multicast address
        if (family == AF_INET)
        {
            if (inet_ntop(AF_INET, &bridge->dst_addr.sin.sin_addr, addr_str, bridge->dst_addr_len) == NULL)
            {
                fatal("inet_ntop failed for IPv4 address: %s\n", strerror(errno));
            }
        }
        else
        {
            if (inet_ntop(AF_INET6, &bridge->dst_addr.sin6.sin6_addr, addr_str, bridge->dst_addr_len) == NULL)
            {
                fatal("inet_ntop failed for IPv6 address: %s\n", strerror(errno));
            }
        }

        // IP type, port and multicast address
        printf("  IPv%u, port %u, address %s\n", (family == AF_INET) ? 4 : 6, bridge->port, addr_str);

        // Inbound interfaces
        printf("    Inbound interfaces:\n");
        for (interface_index = 0; interface_index < bridge->interface_count; interface_index++)
        {
            interface = &bridge->interface_list[interface_index];
            if (interface->inbound_configuration == INTERFACE_CONFIG_NONE)
            {
                continue;
            }

            // Convert the IP address
            if (family == AF_INET)
            {
                if (inet_ntop(AF_INET, &interface->ipv4_addr.s_addr, addr_str, sizeof(addr_str)) == NULL)
                {
                    fatal("inet_ntop failed for IPv4 address: %s\n", strerror(errno));
                }
            }
            else
            {
                if (inet_ntop(AF_INET6, &interface->ipv6_addr.s6_addr, addr_str, sizeof(addr_str)) == NULL)
                {
                    fatal("inet_ntop failed for IPv6 address: %s\n", strerror(errno));
                }
            }

            // Print the interface details
            printf("      %s, %s, address %s\n", interface->name, interface_config_type_to_string(interface->inbound_configuration), addr_str);
        }

        // Outbound interfaces
        printf("    Outbound interfaces:\n");
        for (interface_index = 0; interface_index < bridge->interface_count; interface_index++)
        {
            interface = &bridge->interface_list[interface_index];
            if (interface->outbound_configuration == INTERFACE_CONFIG_NONE)
            {
                continue;
            }

            // Convert the IP address
            if (family == AF_INET)
            {
                if (inet_ntop(AF_INET, &interface->ipv4_addr.s_addr, addr_str, sizeof(addr_str)) == NULL)
                {
                    fatal("inet_ntop failed for IPv4 address: %s\n", strerror(errno));
                }
            }
            else
            {
                if (inet_ntop(AF_INET6, &interface->ipv6_addr.s6_addr, addr_str, sizeof(addr_str)) == NULL)
                {
                    fatal("inet_ntop failed for IPv6 address: %s\n", strerror(errno));
                }
            }

            // Print the interface details
            printf("      %s, %s, address %s\n", interface->name, interface_config_type_to_string(interface->outbound_configuration), addr_str);
        }

        printf("\n");
    }
}
