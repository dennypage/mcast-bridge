
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
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/file.h>

#include "common.h"


// Who we are
static const char *             progname;

// Command line options
static unsigned int             foreground = 0;
static unsigned int             flag_syslog = 0;
unsigned int                    debug_level = 0;
unsigned int                    non_configured_groups = 100;
querier_mode_type_t             igmp_querier_mode = QUERIER_MODE_QUICK;
querier_mode_type_t             mld_querier_mode = QUERIER_MODE_QUICK;


// Process ID file
static const char *             pidfile_name = NULL;

// Config file
#define DEFAULT_CONFIG_FILE     "mcast-bridge.conf"
const char *                    config_filename = DEFAULT_CONFIG_FILE;


//
// Log abnormal events
//
__attribute__ ((format (printf, 1, 2)))
void logger(
    const char *                format,
    ...)
{
    va_list                     args;

    va_start(args, format);
    if (flag_syslog)
    {
        vsyslog(LOG_WARNING, format, args);
    }
    else
    {
        // If foreground and debug is enabled, prepend a timestamp
        if (foreground && debug_level)
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            fprintf(stderr ,"%ld.%06ld: ", (long) ts.tv_sec, ts.tv_nsec / 1000);
        }

        vfprintf(stderr, format, args);
    }
    va_end(args);
}


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
// Termination handler
//
__attribute__ ((noreturn))
static void term_handler(
    int                         signum)
{
    // NB: This function may be simultaneously invoked by multiple threads
    if (pidfile_name)
    {
        (void) unlink(pidfile_name);
    }
    logger("Exiting on signal %d\n", signum);
    exit(0);
}


//
// Usage
//
__attribute__ ((noreturn))
static void usage(
    void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-h] [-f] [-s] [-c config_file] [-p pid_file] [-Q IGMP_querier_mode] [-M MLD_querier_mode] [-D debug_level]\n", progname);
    fprintf(stderr, "  Options:\n");
    fprintf(stderr, "    -h display usage\n");
    fprintf(stderr, "    -f run in foreground\n");
    fprintf(stderr, "    -s log notifications via syslog\n");
    fprintf(stderr, "    -c configuration file name\n");
    fprintf(stderr, "    -p process id file name\n");
    fprintf(stderr, "    -I IGMP querier mode\n");
    fprintf(stderr, "    -M MLD querier mode\n");
    fprintf(stderr, "    -D debug level\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Avalable IGMP/MLD querier modes:\n");
    fprintf(stderr, "    never  Never become a querier\n");
    fprintf(stderr, "    quick  Become a querier immediately at startup (default, RFC behavior)\n");
    fprintf(stderr, "    delay  Become a querier after 125 seconds if no other querier has been seen\n");
    fprintf(stderr, "    defer  Become a querier after 125 seconds if no other querier has been seen\n");
    fprintf(stderr, "           and always defer to any other queriers that may appear regardless of\n");
    fprintf(stderr, "           relative IP address\n");
    exit(1);
}


//
// Parse an IGMP/MLD querier mode
//
static void parse_querier_mode(
    const char *                mode_str,
    querier_mode_type_t *       mode)
{
    printf("optarg: %s\n", mode_str);
    if (strcmp(mode_str, "never") == 0)
    {
        printf("here0\n");
        *mode = QUERIER_MODE_NEVER;
    }
    else if (strcmp(mode_str, "quick") == 0)
    {
        printf("here1\n");
        *mode = QUERIER_MODE_QUICK;
    }
    else if (strcmp(mode_str, "delay") == 0)
    {
        printf("here2\n");
        *mode = QUERIER_MODE_DELAY;
    }
    else if (strcmp(mode_str, "defer") == 0)
    {
        printf("here3\n");
        *mode = QUERIER_MODE_DEFER;
    }
    else
    {
        fprintf(stderr, "Unknown IGMP querier mode \"%s\"\n", mode_str);
        usage();
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

    progname = argv[0];

    while((opt = getopt(argc, argv, "hfsc:p:I:M:D:")) != -1)
    {
        switch (opt)
        {
        case 'f':
            foreground = 1;
            break;
        case 's':
            flag_syslog = 1;
            break;
        case 'c':
            config_filename = optarg;
            break;
        case 'p':
            pidfile_name = optarg;
            break;
        case 'I':
            parse_querier_mode(optarg, &igmp_querier_mode);
            break;
        case 'M':
            parse_querier_mode(optarg, &mld_querier_mode);
            break;
        case 'D':
            debug_level = strtoul(optarg, NULL, 10);
            break;
        default:
            usage();
        }
    }
 }


//
// Create pid file
//
static int create_pidfile(void)
{
    int                         pidfile_fd = -1;
    char                        pidbuf[64];
    pid_t                       pid;
    ssize_t                     rs;
    int                         r;

    // Attempt to create the pid file
    pidfile_fd = open(pidfile_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (pidfile_fd != -1)
    {
        // Lock the pid file
        r = flock(pidfile_fd, LOCK_EX | LOCK_NB);
        if (r == -1)
        {
            fatal("lock of pid file %s failed: %s\n", pidfile_name, strerror(errno));
        }
    }
    else
    {
        // Pid file already exists?
        pidfile_fd = open(pidfile_name, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (pidfile_fd == -1)
        {
            fatal("create/open of pid file %s failed: %s\n", pidfile_name, strerror(errno));
        }

        // Lock the pid file
        r = flock(pidfile_fd, LOCK_EX | LOCK_NB);
        if (r == -1)
        {
            fatal("pid file %s is in use by another process\n", pidfile_name);
        }

        // Check for existing pid
        rs = read(pidfile_fd, pidbuf, sizeof(pidbuf) - 1);
        if (rs > 0)
        {
            pidbuf[rs] = 0;

            pid = (pid_t) strtol(pidbuf, NULL, 10);
            if (pid > 0)
            {
                // Is the pid still alive?
                r = kill(pid, 0);
                if (r == 0)
                {
                    fatal("pid file %s is in use by process %u\n", pidfile_name, (unsigned int) pid);
                }
            }
        }

        // Reset the pid file
        (void) lseek(pidfile_fd, 0, 0);
        r = ftruncate(pidfile_fd, 0);
        if (r == -1)
        {
            fatal("write of pid file %s failed: %s\n", pidfile_name, strerror(errno));
        }
    }

    return pidfile_fd;
}


//
// Write pid file
//
static void write_pidfile(
    int                         pidfile_fd)
{
    char                        pidbuf[64];
    ssize_t                     len;
    ssize_t                     rs;
    int                         r;

    len = snprintf(pidbuf, sizeof(pidbuf), "%u\n", (unsigned) getpid());
    if (len < 0 || (size_t) len > sizeof(pidbuf))
    {
        fatal("error formatting pidfile\n");
    }

    rs = write(pidfile_fd, pidbuf, (size_t) len);
    if (rs == -1)
    {
        fatal("write of pidfile %s failed: %s\n", pidfile_name, strerror(errno));
    }

    r = close(pidfile_fd);
    if (r == -1)
    {
        fatal("close of pidfile %s failed: %s\n", pidfile_name, strerror(errno));
    }
}


//
// Main
//
int main(
    int                         argc,
    char                        *argv[])
{
    int                         pidfile_fd = -1;
    pid_t                       pid;
    struct sigaction            act;

    // Handle command line args
    parse_args(argc, argv);

    // Read config file
    read_config();

    // Dump the configuration
    if (foreground)
    {
        dump_config();
    }

    // Initialize the interfaces
    initialize_interfaces();

    // Termination handler
    memset(&act, 0, sizeof(act));
    act.sa_handler = (void (*)(int)) term_handler;
    (void) sigaction(SIGTERM, &act, NULL);
    (void) sigaction(SIGINT, &act, NULL);

    // Create pid file if requested
    if (pidfile_name)
    {
        pidfile_fd = create_pidfile();
    }

    // Self background
    if (foreground == 0)
    {
        pid = fork();

        if (pid == -1)
        {
            fatal("fork failed: %s\n", strerror(errno));
        }

        if (pid)
        {
            _exit(EXIT_SUCCESS);
        }

        (void) setsid();
    }

    // Write pid file if requested
    if (pidfile_fd != -1)
    {
        write_pidfile(pidfile_fd);
    }

    logger("Mcast Bridge version %s starting\n", VERSION);

    // Initialize IGMP & MLD
    initialize_igmp(foreground);
    initialize_mld(foreground);

    // Drop privileges
    (void) setgid(getgid());
    (void) setuid(getuid());

    // Start IGMP & MLD
    start_igmp();
    start_mld();

    // Start the bridge(s)
    start_bridges();

    // Wait (forever)
    pause();

    return 0;
}
