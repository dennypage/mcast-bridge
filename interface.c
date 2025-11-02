
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


#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"



//
// Bind an IPv4 socket for an interface
//
static void interface_bind_ipv4(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    int                         sock;
    const int                   on = 1;
    const int                   off = 0;
    const int                   ttl = 1;
    int                         r;

    struct sockaddr_in          sin;

    // Create the socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1)
    {
        fatal("IPv4 socket creation failed: %s\n", strerror(errno));
    }

    // Set SO_REUSEADDR and SO_REUSEPORT
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
    }
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEPORT) failed: %s\n", strerror(errno));
    }

    // Set interface specific binding if available
#if defined(SO_BINDTODEVICE)
    r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, bridge_interface->name, strlen(bridge_interface->name));
    if (r == -1)
    {
        fatal("setsockopt (SO_BINDTODEVICE) for IPv4 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }
#elif defined(IP_BOUND_IF)
    r = setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &bridge_interface->if_index, sizeof(interface->if_index));
    if (r == -1)
    {
        fatal("setsockopt (IP_BOUND_IF) for IPv4 on %s failed: %s\n", interface->name, strerror(errno));
    }
#endif

    // Set the ttl
    r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (r == -1)
    {
        fatal("setsockopt (IP_MULTICAST_TTL) for IPv4 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Set the outbound interface
    r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &bridge_interface->ipv4_addr, sizeof(bridge_interface->ipv4_addr));
    if (r == -1)
    {
        fatal("setsockopt (IP_MULTICAST_IF) for IPv4 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Disable multicast loopback
    r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void *) &off, sizeof(off));
    if (r == -1)
    {
        fatal("setsockopt (IP_MULTICAST_LOOP) for IPv4 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Bind the socket
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(bridge->port);
    r = bind(sock, (struct sockaddr *) &sin, sizeof(sin));
    if (r == -1)
    {
        fatal("IPv4 bind on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Set non-blocking
    (void) fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    bridge_interface->sock = sock;
}


//
// Bind an IPv6 socket for an interface
//
static void interface_bind_ipv6(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    int                         sock;
    const int                   on = 1;
    const int                   off = 0;
    const int                   ttl = 1;
    int                         r;

    struct sockaddr_in6         sin6;

    // Create the socket
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1)
    {
        fatal("IPv6 socket creation failed: %s\n", strerror(errno));
    }

    // Ensure we don't end up with a mixed IPv4 / IPv6 socket
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &on, sizeof(on));

    // Set SO_REUSEADDR and SO_REUSEPORT
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
    }
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEPORT) failed: %s\n", strerror(errno));
    }

    // Set interface specific binding if available
#if defined(SO_BINDTODEVICE)
    r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, bridge_interface->name, strlen(bridge_interface->name));
    if (r == -1)
    {
        fatal("setsockopt (SO_BINDTODEVICE) for IPv6 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }
#elif defined(IPV6_BOUND_IF)
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, &bridge_interface->if_index, sizeof(interface->if_index));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_BOUND_IF) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }
#endif

    // Set the ttl
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_UNICAST_HOPS) for IPv6 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Set the outbound interface
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &bridge_interface->if_index, sizeof(bridge_interface->if_index));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_IF) for IPv6 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Disable multicast loopback
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (void *) &off, sizeof(off));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_LOOP) for IPv6 on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Bind the socket
    sin6.sin6_family = AF_INET6;
    memcpy(&sin6.sin6_addr, &in6addr_any, sizeof(sin6.sin6_addr));
    sin6.sin6_port = htons(bridge->port);
    r = bind(sock, (struct sockaddr *) &sin6, sizeof(sin6));
    if (r == -1)
    {
        fatal("IPv6 bind on %s failed: %s\n", bridge_interface->name, strerror(errno));
    }

    // Set non-blocking
    (void) fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    bridge_interface->sock = sock;
}


//
// Activate an inbound interface
//
static void interface_activate_inbound(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    struct ip_mreqn             mreq;
    struct ipv6_mreq            mreq6;
    int                         r;

    // If the interface is already active, ignore the request
    if (bridge_interface->inbound_active)
    {
        return;
    }

    // Debug logging
    if (debug_level)
    {
        logger("Bridge(%s/%u): Activating inbound interface %s (%s)\n",
            AF_FAMILY_TO_STRING(bridge->family), bridge->port, bridge_interface->name,
            interface_config_type_to_string(bridge_interface->inbound_configuration));
    }

    if (bridge->family == AF_INET)
    {
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_ifindex = bridge_interface->if_index;
        mreq.imr_address = bridge_interface->ipv4_addr;
        mreq.imr_multiaddr = bridge->dst_addr.sin.sin_addr;
        r = setsockopt(bridge_interface->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if (r == -1)
        {
            logger("Bridge(IPv4/%u): setsockopt (IP_ADD_MEMBERSHIP) on interface %s failed: %s\n",
                bridge->port, bridge_interface->name, strerror(errno));
        }
    }
    else
    {
        memset(&mreq6, 0, sizeof(mreq6));
        mreq6.ipv6mr_interface = bridge_interface->if_index;
        mreq6.ipv6mr_multiaddr = bridge->dst_addr.sin6.sin6_addr;
        r = setsockopt(bridge_interface->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
        if (r == -1)
        {
            logger("Bridge(IPv6/%u): setsockopt (IPV6_JOIN_GROUP) on interface %s failed: %s\n",
                bridge->port, bridge_interface->name, strerror(errno));
        }
    }

    // Mark the interface as active
    bridge_interface->inbound_active = 1;
}


//
// Deactivate an inbound interface
//
static void interface_deactivate_inbound(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    struct ip_mreqn             mreq;
    struct ipv6_mreq            mreq6;
    int                         r;

    // If the interface is inactive, ignore the request
    if (bridge_interface->inbound_active == 0)
    {
        return;
    }

    // If the interface is not dynamic, ignore the request
    if (bridge_interface->inbound_configuration != INTERFACE_CONFIG_DYNAMIC)
    {
        logger("Bridge(%s/%u): Deactivating non-dynamic inbound interface %s\n",
            AF_FAMILY_TO_STRING(bridge->family), bridge->port, bridge_interface->name);
        return;
    }

    // Debug logging
    if (debug_level)
    {
        logger("Bridge(%s/%u): Deactivating inbound interface %s\n",
            AF_FAMILY_TO_STRING(bridge->family), bridge->port, bridge_interface->name);
    }

    if (bridge->family == AF_INET)
    {
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_ifindex = bridge_interface->if_index;
        mreq.imr_multiaddr = bridge->dst_addr.sin.sin_addr;
        mreq.imr_address = bridge_interface->ipv4_addr;
        r = setsockopt(bridge_interface->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        if (r == -1)
        {
            logger("Bridge(IPv4/%u): setsockopt (IP_DROP_MEMBERSHIP) on interface %s failed: %s\n",
                bridge->port, bridge_interface->name, strerror(errno));
        }
    }
    else
    {
        memset(&mreq6, 0, sizeof(mreq6));
        mreq6.ipv6mr_interface = bridge_interface->if_index;
        mreq6.ipv6mr_multiaddr = bridge->dst_addr.sin6.sin6_addr;
        r = setsockopt(bridge_interface->sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq6, sizeof(mreq6));
        if (r == -1)
        {
            logger("Bridge(IPv6/%u): setsockopt (IPV6_LEAVE_GROUP) on interface %s failed: %s\n",
                bridge->port, bridge_interface->name, strerror(errno));
        }
    }

    // Mark the interface as inactive
    bridge_interface->inbound_active = 0;
}


//
// Activate an outbound interface
//
void interface_activate_outbound(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    bridge_interface_t *        peer;
    unsigned int                peer_index;

    // If the interface is already active, ignore the request
    if (bridge_interface->outbound_active)
    {
        return;
    }

    // Debug logging
    if (debug_level)
    {
        logger("Bridge(%s/%u): Activating outbound interface %s (%s)\n",
            AF_FAMILY_TO_STRING(bridge->family), bridge->port, bridge_interface->name,
            interface_config_type_to_string(bridge_interface->outbound_configuration));
    }

    // Mark the interface as active
    bridge_interface->outbound_active = 1;

    // Activate inbound dynamic peers
    for (peer_index = 0; peer_index < bridge->interface_count; peer_index++)
    {
        peer = &bridge->interface_list[peer_index];
        if (peer == bridge_interface)
        {
            continue;
        }
        if (peer->inbound_configuration == INTERFACE_CONFIG_DYNAMIC)
        {
            interface_activate_inbound(peer);
        }
    }
}


//
// Deactivate an outbound interface
//
void interface_deactivate_outbound(
    bridge_interface_t *        bridge_interface)
{
    bridge_instance_t *         bridge = &bridge_list[bridge_interface->bridge_index];
    bridge_interface_t *        peer;
    unsigned int                peer_index;
    bridge_interface_t *        peer2;
    unsigned int                peer2_index;

    // If the interface is inactive, ignore the request
    if (bridge_interface->outbound_active == 0)
    {
        return;
    }

    // If the interface is not dynamic, ignore the request
    if (bridge_interface->outbound_configuration != INTERFACE_CONFIG_DYNAMIC)
    {
        logger("Bridge(%s/%u): Deactivating non-dynamic outbound interface %s\n",
            AF_FAMILY_TO_STRING(bridge->family), bridge->port, bridge_interface->name);
        return;
    }

    // Debug logging
    if (debug_level)
    {
        logger("Bridge(%s/%u): Deactivating outbound interface %s\n",
            AF_FAMILY_TO_STRING(bridge->family), bridge->port, bridge_interface->name);
    }

    // Mark the interface as inactive
    bridge_interface->outbound_active = 0;

    // Deactivate inbound dynamic peers if appropriate
    for (peer_index = 0; peer_index < bridge->interface_count; peer_index++)
    {
        peer = &bridge->interface_list[peer_index];
        if (peer == bridge_interface || peer->inbound_configuration != INTERFACE_CONFIG_DYNAMIC)
        {
            continue;
        }

        for (peer2_index = 0; peer2_index < bridge->interface_count; peer2_index++)
        {
            peer2 = &bridge->interface_list[peer2_index];
            if (peer2 == peer)
            {
                continue;
            }

            if (peer2->outbound_active)
            {
                break;
            }
        }
        if (peer2_index >= bridge->interface_count)
        {
            interface_deactivate_inbound(peer);
        }
    }
}


//
// Initialize the interfaces
//
void initialize_interfaces(void)
{
    bridge_instance_t *         bridge;
    bridge_interface_t *        bridge_interface;
    unsigned int                bridge_index;
    unsigned int                interface_index;

    // Iterate over the bridge instances and bind the interface sockets
    for (bridge_index = 0; bridge_index < bridge_list_count; bridge_index++)
    {
        bridge = &bridge_list[bridge_index];

        for (interface_index = 0; interface_index < bridge->interface_count; interface_index++)
        {
            bridge_interface = &bridge->interface_list[interface_index];
            if (bridge->family == AF_INET)
            {
                interface_bind_ipv4(bridge_interface);
            }
            else
            {
                interface_bind_ipv6(bridge_interface);
            }
        }
    }

    // Iterate over the bridge instances and activate or register as appropriate
    for (bridge_index = 0; bridge_index < bridge_list_count; bridge_index++)
    {
        bridge = &bridge_list[bridge_index];

        for (interface_index = 0; interface_index < bridge->interface_count; interface_index++)
        {
            bridge_interface = &bridge->interface_list[interface_index];

            // If the inbound interface is not dynamic, activate it
            if (bridge_interface->inbound_configuration != INTERFACE_CONFIG_DYNAMIC)
            {
                interface_activate_inbound(bridge_interface);
            }

            // If the outbound interface is dynamic, register it, otherwise activate it
            if (bridge_interface->outbound_configuration == INTERFACE_CONFIG_DYNAMIC)
            {
                if (bridge->family == AF_INET)
                {
                    igmp_register_interface(bridge_interface);
                }
                else
                {
                    mld_register_interface(bridge_interface);
                }
            }
            else
            {
                interface_activate_outbound(bridge_interface);
            }
        }
    }
}
