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


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>


// Defaults:
//
//   IPv4 group address is 239.0.75.0
//   IPv6 group address is ff05:0:0:0:0:0:0:7500
//   Port is 7500
//
#define DEFAULT_IPV4_GROUP      0xef004b00
#define DEFAULT_IPV6_GROUP      {{{ 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x75, 0x00 }}}
#define DEFAULT_PORT            7500

// Who we are
static const char *             progname;

// Command line options
static unsigned int             ip_version = 4;
static unsigned int             numeric = 0;
static unsigned int             send_mode = 0;
static char *                   interface_name = "(default)";
static unsigned int             interface_index = 0;
static unsigned int             port = DEFAULT_PORT;

// Group address structures
static struct sockaddr_in       ipv4_group_sockaddr_in;
static struct sockaddr_in6      ipv6_group_sockaddr_in6;
static struct sockaddr *        group_addr;
static socklen_t                group_addr_len;


//
// Report a fatal error
//
__attribute__ ((noreturn, format (printf, 1, 2)))
void fatal(
    const char *                format,
    ...)
{
    va_list                     args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}


//
// Bind for IPv4
//
static int bind_ipv4(
    unsigned int                join)
{
    int                         sock;
    const int                   on = 1;
    const int                   ttl = 1;
    struct ip_mreqn             mreqn;
    int                         r;
    struct sockaddr_in          bind_sockaddr =
    {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port)
    };

    // Set the interface index in the mreqn structure
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = interface_index;

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

    if (interface_index)
    {
        // Set interface specific binding if available
#if defined(SO_BINDTODEVICE)
        r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name));
        if (r == -1)
        {
            fatal("setsockopt (SO_BINDTODEVICE) for IPv4 on %s failed: %s\n", interface_name, strerror(errno));
        }
#elif defined(IP_BOUND_IF)
        r = setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &interface_index, sizeof(interface_index));
        if (r == -1)
        {
            fatal("setsockopt (IP_BOUND_IF) for IPv4 on %s failed: %s\n", interface_name, strerror(errno));
        }
#endif

        // Set the outbound interface
        r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn));
        if (r == -1)
        {
            fatal("setsockopt (IP_MULTICAST_IF) for IPv4 on %s failed: %s\n", interface_name, strerror(errno));
        }
    }

    // Set the ttl
    r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_IF) for IPv6 on %s failed: %s\n", interface_name, strerror(errno));
    }

    // Bind the socket
    r = bind(sock, (struct sockaddr *) &bind_sockaddr, sizeof(bind_sockaddr));
    if (r == -1)
    {
        fatal("IPv4 bind on %s failed: %s\n", interface_name, strerror(errno));
    }

    if (join)
    {
        // Join the multicast group
        mreqn.imr_multiaddr = ipv4_group_sockaddr_in.sin_addr;
        r = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn));
        if (r == -1)
        {
            fatal("setsockopt (IP_ADD_MEMBERSHIP) for IPv4 on %s failed: %s\n", interface_name, strerror(errno));
        }
    }

    return sock;
}


//
// Bind for IPv6
//
static int bind_ipv6(
    unsigned int                join)
{
    int                         sock;
    const int                   on = 1;
    const int                   ttl = 1;
    struct ipv6_mreq            mreq6;
    int                         r;
    struct sockaddr_in6         bind_sockaddr =
    {
        .sin6_family=AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(port),
    };

    // Set the interface index in the mreq6 structure
    memset(&mreq6, 0, sizeof(mreq6));
    mreq6.ipv6mr_interface = interface_index;

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

    if (interface_index)
    {
        // Set interface specific binding if available
#if defined(SO_BINDTODEVICE)
        r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name));
        if (r == -1)
        {
            fatal("setsockopt (SO_BINDTODEVICE) for IPv6 on %s failed: %s\n", interface_name, strerror(errno));
        }
#elif defined(IPV6_BOUND_IF)
        r = setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, &interface_index, sizeof(interface_index));
        if (r == -1)
        {
            fatal("setsockopt (IPV6_BOUND_IF) for IPv6 on %s failed: %s\n", interface_name, strerror(errno));
        }
#endif

        // Set the outbound interface
        r = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface_index, sizeof(interface_index));
        if (r == -1)
        {
            fatal("setsockopt (IPV6_MULTICAST_IF) for IPv6 on %s failed: %s\n", interface_name, strerror(errno));
        }
    }

    // Set the ttl
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_IF) for IPv6 on %s failed: %s\n", interface_name, strerror(errno));
    }

    // Bind the socket
    r = bind(sock, (struct sockaddr *) &bind_sockaddr, sizeof(bind_sockaddr));
    if (r == -1)
    {
        fatal("IPv6 bind on %s failed: %s\n", interface_name, strerror(errno));
    }

    if (join)
    {
        // Join the multicast group
        mreq6.ipv6mr_multiaddr = ipv6_group_sockaddr_in6.sin6_addr;
        r = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
        if (r == -1)
        {
            fatal("setsockopt (IPV6_JOIN_GROUP) for IPv6 on %s failed: %s\n", interface_name, strerror(errno));
        }
    }

    return sock;
}


//
// Sender loop
//
__attribute__ ((noreturn))
static void sender(
    int                         sock)
{
    int                         r;
    char                        buffer[64];

    while (1)
    {
        snprintf(buffer, sizeof(buffer), "%ld", time(NULL));
        r = sendto(sock, buffer, strlen(buffer) + 1, 0, group_addr, group_addr_len);
        if (r == -1 )
        {
            fatal("sendto error: %s\n", strerror(errno));
        }
        printf("Sent %ld bytes: %s\n", strlen(buffer),  buffer);

        sleep(1);
    }
}


//
// Receiver loop
//
__attribute__ ((noreturn))
static void receiver(
    int                         sock)
{
    struct sockaddr_storage     src_addr_storage;
    struct sockaddr *           src_addr = (struct sockaddr *) &src_addr_storage;
    socklen_t                   src_addr_len;
    ssize_t                     bytes;
    char                        src_addr_str[NI_MAXHOST];
    char                        buffer[64];

    while (1)
    {
        src_addr_len = sizeof(src_addr_storage);
        bytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                                src_addr, &src_addr_len);

        if (bytes == -1)
        {
            fatal("recvfrom error: %s\n", strerror(errno));
        }
        if (bytes == sizeof(buffer))
        {
            // Message was truncated
            buffer[sizeof(buffer) - 1] = '\0';
        }

        getnameinfo(src_addr, src_addr_len, src_addr_str, sizeof(src_addr_str), NULL, 0, numeric);
        port = ntohs(((struct sockaddr_in *) src_addr)->sin_port);
        printf("Received %ld bytes from %s: %s\n", bytes, src_addr_str, buffer);
    }
}


//
// Parse command line arguments
//
static void parse_args(
    int                         argc,
    char * const                argv[])
{
    int                         opt;
    int                         r;
    char                        addr_str[INET6_ADDRSTRLEN];

    progname = argv[0];

    while((opt = getopt(argc, argv, "h46nsi:p:")) != -1)
    {
        switch (opt)
        {
        case '4':
            ip_version = 4;
            break;

        case '6':
            ip_version = 6;
            break;

        case 'n':
            numeric = NI_NUMERICHOST;
            break;

        case 's':
            send_mode = 1;
            break;

        case 'i':
            interface_name = optarg;
            interface_index = if_nametoindex(interface_name);
            if (interface_index == 0)
            {
                fatal("Interface \"%s\" does not exist\n", interface_name);
            }
            break;

        case 'p':
            // Insure the port number is valid
            if (strlen(optarg) && strspn(optarg, "0123456789") == strlen(optarg))
            {
                port = strtoul(optarg, NULL, 10);
            }
            if (port < 1 || port > 65535)
            {
                fatal("Invalid port number \"%s\"\n", optarg);
            }

            ipv4_group_sockaddr_in.sin_port = htons(port);
            ipv6_group_sockaddr_in6.sin6_port = htons(port);
            break;

        default:
            fprintf(stderr, "Usage:\n");
            fprintf(stderr, "  %s [-4|-6] [-n] [-s] [-i interface] [-p port] [multicast address]\n", progname);
            fprintf(stderr, "\n");
            fprintf(stderr, "  options:\n");
            fprintf(stderr, "    -4 IP version 4 (default)\n");
            fprintf(stderr, "    -6 IP version 6\n");
            fprintf(stderr, "    -n numeric hostnames\n");
            fprintf(stderr, "    -s sender mode\n");
            fprintf(stderr, "    -i interface name (default is the system default interface)\n");
            fprintf(stderr, "    -p UDP port (default is 7500)\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "  the default multicast address for IP version 4 is %s\n",
                inet_ntop(AF_INET, &ipv4_group_sockaddr_in.sin_addr, addr_str, sizeof(addr_str)));
            fprintf(stderr, "  the default multicast address for IP version 6 is %s\n",
                inet_ntop(AF_INET6, &ipv6_group_sockaddr_in6.sin6_addr, addr_str, sizeof(addr_str)));
            exit(1);
        }
    }

    // Handle the multicast address argument
    if (optind < argc)
    {
        if (ip_version == 4)
        {
            r = inet_pton(AF_INET, argv[optind], &ipv4_group_sockaddr_in.sin_addr);
            if (r == 0 || IN_MULTICAST(ntohl(ipv4_group_sockaddr_in.sin_addr.s_addr)) == 0)
            {
                fatal("Invalid IPv4 multicast group address \"%s\"\n", argv[optind]);
            }
        }
        else
        {
            r = inet_pton(AF_INET6, argv[optind], &ipv6_group_sockaddr_in6.sin6_addr);
            if (r == 0 || IN6_IS_ADDR_MULTICAST(&ipv6_group_sockaddr_in6.sin6_addr) == 0)
            {
                fatal("Invalid IPv6 address \"%s\"\n", argv[optind]);
            }
        }
    }
 }


//
// Main
//
int main(
    int                         argc,
    char                        *argv[])
{
    int                         sock;
    char                        addr_str[INET_ADDRSTRLEN];

    // Initialize default addresses
    const struct sockaddr_in    default_ipv4_group_sockaddr =
    {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(DEFAULT_IPV4_GROUP),
        .sin_port = htons(DEFAULT_PORT)
    };
    const struct sockaddr_in6   default_ipv6_group_sockaddr =
    {
        .sin6_family=AF_INET6,
        .sin6_addr = DEFAULT_IPV6_GROUP,
        .sin6_port = htons(DEFAULT_PORT),
    };

    // Set default addresses
    ipv4_group_sockaddr_in = default_ipv4_group_sockaddr;
    ipv6_group_sockaddr_in6 = default_ipv6_group_sockaddr;

    // Handle command line args
    parse_args(argc, argv);

    // Bind the socket
    if (ip_version == 4)
    {
        group_addr = (struct sockaddr *) &ipv4_group_sockaddr_in;
        group_addr_len = sizeof(ipv4_group_sockaddr_in);

        printf("%s to port %d and multicast group %s on interface %s (%d)\n",
            send_mode ? "Sending" : "Listening", port,
            inet_ntop(AF_INET, &ipv4_group_sockaddr_in.sin_addr, addr_str, sizeof(addr_str)),
            interface_name, interface_index);

        sock = bind_ipv4(send_mode == 0);
    }
    else
    {
        group_addr = (struct sockaddr *) &ipv6_group_sockaddr_in6;
        group_addr_len = sizeof(ipv6_group_sockaddr_in6);
        ipv6_group_sockaddr_in6.sin6_scope_id = interface_index;

        printf("%s to port %d and multicast group %s on interface %s (%d)\n",
            send_mode ? "Sending" : "Listening", port,
            inet_ntop(AF_INET6, &ipv6_group_sockaddr_in6.sin6_addr, addr_str, sizeof(addr_str)),
            interface_name, interface_index);

        sock = bind_ipv6(send_mode == 0);
    }

    // Enter the send or receive loop
    if (send_mode)
    {
        sender(sock);
    }
    else
    {
        receiver(sock);
    }
}
