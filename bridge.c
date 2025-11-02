
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"



// Thread local storage for bridge threads
typedef struct
{
    bridge_instance_t *         bridge;
    evm_t *                     evm;
    unsigned char               packet_buffer[MCAST_MAX_PACKET_SIZE];
} bridge_local_storage_t;


// Thread local storage key
static pthread_key_t            thread_local_storage_key;


//
// Process an incoming packet
//
static void bridge_receive(
    void *                      arg)
{
    bridge_interface_t *        bridge_interface = arg;
    bridge_instance_t *         bridge;
    bridge_local_storage_t *    local_storage;
    ssize_t                     bytes;
    socket_address_t            src_addr;
    socklen_t                   src_addr_len;
    socket_address_t *          dst_addr;
    socklen_t                   dst_addr_len;
    bridge_interface_t *        peer;
    unsigned int                peer_index;
    char                        src_addr_str[INET6_ADDRSTRLEN] = {0};

    // Get the thread local storage
    local_storage = pthread_getspecific(thread_local_storage_key);
    if (local_storage == NULL)
    {
        fatal("pthread_getspecific failed\n");
    }

    // Get the bridge instance
    bridge = &bridge_list[bridge_interface->bridge_index];
    dst_addr = &bridge->dst_addr;
    dst_addr_len = bridge->dst_addr_len;

    // Receive the packet
    src_addr_len = sizeof(src_addr.storage);
    bytes = recvfrom(bridge_interface->sock,
                            local_storage->packet_buffer, sizeof(local_storage->packet_buffer), 0,
                            &src_addr.sa, &src_addr_len);
    if (bytes == -1)
    {
        logger("Bridge(%s/%u): recvfrom error on interface %s: %s\n",
            AF_FAMILY_TO_STRING(bridge->family), bridge->port,
            bridge_interface->name, strerror(errno));
        return;
    }

    // If the interface is not active, drop the packet
    if (bridge_interface->inbound_active == 0)
    {
        return;
    }

    // Save the source address for logging
    if (debug_level >= 4)
    {
        if (bridge->family == AF_INET)
        {
            inet_ntop(AF_INET, &src_addr.sin.sin_addr, src_addr_str, sizeof(src_addr_str));
        }
        else
        {
            inet_ntop(AF_INET6, &src_addr.sin6.sin6_addr, src_addr_str, sizeof(src_addr_str));
        }
    }

    // Forward the packet to outbound peer interfaces
    for (peer_index = 0; peer_index < bridge->interface_count; peer_index++)
    {
        peer = &bridge->interface_list[peer_index];

        // If the peer is me, or the peer is not active, skip it
        if (peer == bridge_interface || peer->outbound_active == 0)
        {
            continue;
        }

        if (bridge->family == AF_INET6)
        {
            // Set the destination scope ID
            dst_addr->sin6.sin6_scope_id = peer->if_index;
        }

        // Send the packet
        if (sendto(peer->sock, local_storage->packet_buffer, bytes, 0, &dst_addr->sa, dst_addr_len) == -1)
        {
            logger("Bridge(%s/%u): sendto error on interface %s: %s\n",
                AF_FAMILY_TO_STRING(bridge->family), bridge->port,
                peer->name, strerror(errno));
            continue;
        }

        if (debug_level >= 4)
        {
            logger("Bridge(%s/%u): Forwarded %lu bytes from %s on %s to %s\n",
                AF_FAMILY_TO_STRING(bridge->family), bridge->port, (unsigned long) bytes,
                src_addr_str, bridge_interface->name, peer->name);
        }
    }
}


//
// Bridge thread
//
__attribute__ ((noreturn))
static void * bridge_thread(
    void *                      arg)
{
    bridge_local_storage_t *    local_storage = (bridge_local_storage_t *) arg;
    int                         r;

    // Set the thread local storage
    r = pthread_setspecific(thread_local_storage_key, local_storage);
    if (r)
    {
        fatal("pthread_setspecific: %s\n", strerror(r));
    }

    // Run the event loop
    evm_loop(local_storage->evm);
}


//
// Start the bridge threads
//
void start_bridges(void)
{
    bridge_instance_t *         bridge;
    bridge_interface_t *        bridge_interface;
    unsigned int                bridge_index;
    unsigned int                interface_index;
    bridge_local_storage_t *    local_storage;
    pthread_t                   thread_id;
    int                         r;

    // Create the thread local storage key
    r = pthread_key_create(&thread_local_storage_key, NULL);
    if (r)
    {
        fatal("pthread_key_create: %s\n", strerror(r));
    }

    // Start the bridge threads. Each bridge instance (IP family & port number) has its own thread.
    // NB: All but the last thread ID created is discarded/lost.
    for (bridge_index = 0; bridge_index < bridge_list_count; bridge_index++)
    {
        bridge = &bridge_list[bridge_index];

        // Allocate the thread local storage
        local_storage = calloc(1, sizeof(bridge_local_storage_t));
        if (local_storage == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }
        local_storage->bridge = bridge;


        // Create the event manager
        local_storage->evm = evm_create(bridge->interface_count, 0);
        if (local_storage->evm == NULL)
        {
            fatal("Cannot create event manager\n");
        }

        // Add the interface sockets to the event manager
        for (interface_index = 0; interface_index < bridge->interface_count; interface_index++)
        {
            bridge_interface = &bridge->interface_list[interface_index];

            evm_add_socket(local_storage->evm, bridge_interface->sock,
                bridge_receive, bridge_interface);
        }

        // Start the thread
        r = pthread_create(&thread_id, NULL, &bridge_thread, local_storage);
        if (r != 0)
        {
            fatal("cannot create bridge thread: %s\n", strerror(errno));
        }
    }
}
