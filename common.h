
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


#ifndef _COMMON_H
#define _COMMON_H 1

#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>


// Version number of mcast-bridge
#define VERSION                 "1.2.0"


// Maximum packet size for UDP packet we support. Note that this limit
// cannot be reached in practice with IPv4 due to the length limit of
// IP packet. The practical limit for IPv4 is 65507. IPv6 in theory
// allows for "jumbograms" which could arbitrarially exceed the 65535
// byte limit, but in general practice the limit for IPv6 is 65495.
#define MCAST_MAX_PACKET_SIZE   65535


// Map an address family to a string
#define AF_FAMILY_TO_STRING(family) ((family) == AF_INET ? "IPv4" : "IPv6")


//
// Common types and structures
//

// Socket address structure
typedef union
{
    struct sockaddr_in          sin;
    struct sockaddr_in6         sin6;
    struct sockaddr_storage     storage;
    struct sockaddr             sa;
} socket_address_t;

// Interface configuration type
typedef enum interface_config_type
{
    INTERFACE_CONFIG_NONE       = 0,
    INTERFACE_CONFIG_DYNAMIC    = 1,
    INTERFACE_CONFIG_STATIC     = 2,
    INTERFACE_CONFIG_FORCED     = 3
} interface_config_type_t;

// Interface structure
typedef struct bridge_interface
{
    // The bridge instance this interface belongs to
    unsigned int                bridge_index;

    // Interface socket
    int                         sock;

    // What is the interface configured for?
    interface_config_type_t     inbound_configuration;
    interface_config_type_t     outbound_configuration;

    // Is the interface currently active?
    unsigned int                inbound_active;
    unsigned int                outbound_active;

    // Interface name, index and addresses
    char *                      name;
    unsigned int                if_index;
    struct in_addr              ipv4_addr;
    struct in6_addr             ipv6_addr;
    struct in6_addr             ipv6_addr_ll;
    uint8_t                     mac_addr[6];
} bridge_interface_t;


// Instance structure
typedef struct bridge_instance
{
    // IP type and port number
    unsigned short              family;
    unsigned short              port;

    // Multicast address
    socket_address_t            dst_addr;
    socklen_t                   dst_addr_len;

    // Interfaces that are part of this bridge instance
    bridge_interface_t *        interface_list;
    unsigned int                interface_count;
} bridge_instance_t;


// Event manager types
typedef void *                  evm_t;
typedef void                    (*evm_callback_t) (void * closure);

// Querier mode type
typedef enum querier_mode_type
{
    QUERIER_MODE_NEVER          = 0,
    QUERIER_MODE_QUICK          = 1,
    QUERIER_MODE_DELAY          = 2,
    QUERIER_MODE_DEFER          = 3
} querier_mode_type_t;


//
// Global definitions
//

// Configuration items, defined in main.c
extern const char *             config_filename;
extern unsigned int             non_configured_groups;
extern querier_mode_type_t      igmp_querier_mode;
extern querier_mode_type_t      mld_querier_mode;

// Debug level, defined in main.c
// 0 = No debuging
// 1 = Interface activations/deactivations
// 2 = IGMP/MLD packet issues
// 3 = IGMP/MLD send and receive
// 4 = Bridge packet forwarding detail
extern unsigned int             debug_level;

// Instances, defined in config.c
extern bridge_instance_t *      bridge_list;
extern unsigned int             bridge_list_allocated;
extern unsigned int             bridge_list_count;


//
// Global functions
//

// Log for abnormal events
__attribute__ ((format (printf, 1, 2)))
extern void logger(
    const char *       format,
    ...);

// Fatal error
__attribute__ ((noreturn, format (printf, 1, 2)))
extern void fatal(
    const char *       format,
    ...);

// Config processing
extern void read_config(void);
extern void dump_config(void);

// Map an interface configuration type to a string
char * interface_config_type_to_string(
    interface_config_type_t     interface_config_type);

// Initialize the socket infrastructure
extern void initialize_interfaces(void);

// Activate an outbound interface
extern void interface_activate_outbound(
    bridge_interface_t *      bridge_interface);

// Deactivate an outbound interface
extern void interface_deactivate_outbound(
    bridge_interface_t *      bridge_interface);

// Register IGMP interest for an interface
extern void igmp_register_interface(
    bridge_interface_t *      bridge_interface);

// Register IGMP interest for an interface
extern void mld_register_interface(
    bridge_interface_t *      bridge_interface);

// Create an event manager instance
void * evm_create(
    int                         max_socket_count,
    int                         max_timer_count);

// Add a socket to the event manager
extern void evm_add_socket(
    evm_t *                     evm,
    int                         fd,
    evm_callback_t              callback,
    void *                      closure);

// Add a timer to the event manager
extern void evm_add_timer(
    evm_t *                     evm,
    unsigned int                millis,
    evm_callback_t              callback,
    void *                      closure);

// Delete a timer from the event manager
extern void evm_del_timer(
    evm_t *                     evm,
    evm_callback_t              callback,
    void *                      closure);

// Event manager loop
__attribute__ ((noreturn))
void evm_loop(
    evm_t *                     evm);

// Initialize the IGMP infrastructure
extern void initialize_igmp(
    unsigned int                dump_config
);

// Initialize the MLD infrastructure
extern void initialize_mld(
    unsigned int                dump_config
);

// The igmp loop
extern void start_igmp(void);

// The mld loop
extern void start_mld(void);

// The main bridge loops
extern void start_bridges(void);

// Calculate the relative number of milliseconds between ts1 and ts2
extern long timespec_delta_millis(
    const struct timespec *     ts1,
    const struct timespec *     ts2);

// Calculate an internet checksum
uint16_t inet_csum(
    const uint16_t *            addr,
    int                         len);

// Calculate an internet v6 checksum
uint16_t inet6_csum(
    const uint16_t *            addr,
    int                         len,
    const uint16_t *            src_addr,
    const uint16_t *            dst_addr,
    uint8_t                     next_header);

// Decode an 8-bit timecode value (IGMPv3 & MLDv2)
uint16_t timecode_8bit_decode(
    uint8_t                     code);

// Decode an 16-bit timecode value (MLDv2)
uint32_t timecode_16bit_decode(
    uint16_t                     code);

#endif // _COMMON_H
