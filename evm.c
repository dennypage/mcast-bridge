
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
#include <time.h>
#include <errno.h>

#include "common.h"


//
// Note, this is a restricted use event manager:
// The maximum number of socket and timer events is fixed at evm creation
// to allow for preallocation of all memory. Malloc/calloc is not called
// after evm creation.
// The only socket event type is read available.
// There is no way to remove a socket event.
// The number of timers is expected to be very small.
// Timer events resolution is 1 millisecond.
// Timer callback/closure is used as the identifier for timer deletion.
//



//
// Ensure we have epoll or kqueue
//
#if defined(__linux__)
# define HAVE_EPOLL
#elif defined(__FreeBSD__) || defined(__APPLE__)
# define HAVE_KQUEUE
#endif

#if defined(HAVE_EPOLL)
# include <sys/epoll.h>
#elif defined(HAVE_KQUEUE)
# include <sys/event.h>
#else
# error epoll or kqueue is required
#endif



//
// Intenral event manager structures
//
typedef struct socket_event
{
    int                         fd;
    evm_callback_t              callback;
    void *                      closure;
} socket_event_t;

typedef struct timer_event
{
    struct timespec             timespec;
    evm_callback_t              callback;
    void *                      closure;
} timer_event_t;

typedef struct _evm
{
    socket_event_t *            socket_list;
    int                         socket_list_allocated;
    int                         socket_list_count;

    timer_event_t *             timer_list;
    int                         timer_list_allocated;
    int                         timer_list_count;

    int                         event_fd;
#if defined(HAVE_EPOLL)
    struct epoll_event *        events;
#elif defined(HAVE_KQUEUE)
    struct kevent *             events;
#endif
} _evm_t;


//
// Create an event manager instance
//
// NB: FD and timer counts are used to preallocate memory.
//
void * evm_create(
    int                         max_socket_count,
    int                         max_timer_count)
{
    _evm_t *                    evm;

    evm = calloc(1, sizeof(_evm_t));
    if (evm == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // Allocate the FD list
    if (max_socket_count)
    {
        evm->socket_list = calloc(max_socket_count, sizeof(socket_event_t));
        evm->socket_list_allocated = max_socket_count;

#if defined(HAVE_EPOLL)
        // Create the kernel event notifier
        evm->event_fd = epoll_create(max_socket_count);
        if (evm->event_fd < 0)
        {
            fatal("epoll_create: %s\n", strerror(errno));
        }

        // Create the socket event list
        evm->events = calloc(max_socket_count, sizeof(struct epoll_event));
        if (evm->events == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }
#elif defined(HAVE_KQUEUE)
        // Create the kernel event notifier
        evm->event_fd = kqueue();
        if (evm->event_fd < 0)
        {
            fatal("kqueue: %s\n", strerror(errno));
        }

        // Create the socket event list
        evm->events = calloc(max_socket_count, sizeof(struct kevent));
        if (evm->events == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }
#endif

    }

    // Allocate the timer list
    if (max_timer_count)
    {
        evm->timer_list = calloc(max_timer_count, sizeof(timer_event_t));
        evm->timer_list_allocated = max_timer_count;
    }

    return evm;
}


//
// Add an socket to the event manager
//
void evm_add_socket(
    evm_t *                     evm_p,
    int                         fd,
    evm_callback_t              callback,
    void *                      closure)
{
    _evm_t *                    evm = (_evm_t *) evm_p;
    int                         r;

    if (evm->socket_list_count >= evm->socket_list_allocated)
    {
        fatal("evm_add_fd: Number of FDs (%d) exceeded.\n", evm->socket_list_allocated);
    }

    evm->socket_list[evm->socket_list_count].fd = fd;
    evm->socket_list[evm->socket_list_count].callback = callback;
    evm->socket_list[evm->socket_list_count].closure = closure;

#if defined(HAVE_EPOLL)
    {
        struct epoll_event      event;

        event.events = EPOLLIN;
        event.data.ptr = &evm->socket_list[evm->socket_list_count];
        r = epoll_ctl(evm->event_fd, EPOLL_CTL_ADD, fd, &event);
        if (r < 0)
        {
            fatal("epoll_ctl (EPOLL_CTL_ADD): %s\n", strerror(errno));
        }
    }
#elif defined(HAVE_KQUEUE)
    {
        struct kevent           event;

        EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, &evm->socket_list[evm->socket_list_count]);
        r = kevent(evm->event_fd, &event, 1, NULL, 0, NULL);
        if (r < 0)
        {
            fatal("kevent (EV_SET): %s\n", strerror(errno));
        }
    }
#endif

    evm->socket_list_count += 1;
}


//
// Add a timer to the event manager
//
void evm_add_timer(
    evm_t *                     evm_p,
    unsigned int                millis,
    evm_callback_t              callback,
    void *                      closure)
{
    _evm_t *                    evm = (_evm_t *) evm_p;
    struct timespec             now;
    long                        sec;
    long                        nsec;
    int                         index;

    if (evm->timer_list_count >= evm->timer_list_allocated)
    {
        logger("evm_add_timer: Number of timers (%d) exceeded\n", evm->timer_list_allocated);
        return;
    }

    // Get the current time
    clock_gettime(CLOCK_MONOTONIC, &now);

    // Calculate the expiration time
    sec = now.tv_sec + millis / 1000;
    nsec = now.tv_nsec + (millis % 1000) * 1000000L;
    if (nsec >= 1000000000L)
    {
        sec += 1;
        nsec -= 1000000000L;
    }

    // Find where in the list the timer should be inserted
    // NB: the number of timers is expected to be small, so a linear search is acceptable
    for (index = 0; index < evm->timer_list_count; index++)
    {
        if (sec < evm->timer_list[index].timespec.tv_sec ||
            (sec == evm->timer_list[index].timespec.tv_sec &&
             nsec < evm->timer_list[index].timespec.tv_nsec))
        {
            break;
        }
    }

    // Open the array if needed
    if (index < evm->timer_list_count)
    {
        memmove(&evm->timer_list[index + 1], &evm->timer_list[index], (evm->timer_list_count - index) * sizeof(timer_event_t));
    }

    // Set the timer
    evm->timer_list[index].timespec.tv_sec = sec;
    evm->timer_list[index].timespec.tv_nsec = nsec;
    evm->timer_list[index].callback = callback;
    evm->timer_list[index].closure = closure;
    evm->timer_list_count += 1;
}


//
// Delete a timer from the event manager
//
void evm_del_timer(
    evm_t *                     evm_p,
    evm_callback_t              callback,
    void *                      closure)
{
    _evm_t *                    evm = (_evm_t *) evm_p;
    int                         index;

    // Find the timer in the list
    for (index = 0; index < evm->timer_list_count; index++)
    {
        if (evm->timer_list[index].callback == callback && evm->timer_list[index].closure == closure)
        {
            // Remove the timer
            evm->timer_list_count -= 1;
            if (evm->timer_list_count > 0)
            {
                memmove(&evm->timer_list[index], &evm->timer_list[index + 1], (evm->timer_list_count - index) * sizeof(timer_event_t));
            }
           break;
        }
    }
}


//
// Event manager loop
//
__attribute__ ((noreturn))
void evm_loop(
    evm_t *                     evm_p)
{
    _evm_t *                    evm = (_evm_t *) evm_p;
    struct timespec             now;
    long                        timeout;
    socket_event_t *            evm_socket;
    int                         num_events;
    int                         index;
    evm_callback_t              timer_callback;
    void *                      timer_closure;

    while (1)
    {
        // Calculate the timeout
        if (evm->timer_list_count)
        {
            // Get the current time
            clock_gettime(CLOCK_MONOTONIC, &now);

            // Calculate the timeout (1ms minimum)
            timeout = timespec_delta_millis(&now, &evm->timer_list[0].timespec);
            if (timeout < 1)
            {
                timeout = 1;
            }
        }
        else
        {
            timeout = -1;
        }

        // Wait for events
#if defined(HAVE_EPOLL)
        num_events = epoll_wait(evm->event_fd, evm->events, evm->socket_list_count, timeout);
        if (num_events < 0 && errno != EINTR)
        {
            logger("epoll_wait: %s\n", strerror(errno));
        }
#elif defined(HAVE_KQUEUE)
        {
            struct timespec     ts;
            struct timespec *   tsp = NULL;

            // Convert the timeout to a timespec
            if (timeout > 0)
            {
                ts.tv_sec = timeout / 1000;
                ts.tv_nsec = (timeout % 1000) * 1000000L;
                tsp = &ts;
            }

            num_events = kevent(evm->event_fd, NULL, 0, evm->events, evm->socket_list_count, tsp);
            if (num_events < 0 && errno != EINTR)
            {
                logger("kevent: %s\n", strerror(errno));
            }
        }
#endif

        // Dispatch IO events
        for (index = 0; index < num_events; index++)
        {
#if defined(HAVE_EPOLL)
            evm_socket = evm->events[index].data.ptr;
#elif defined(HAVE_KQUEUE)
            evm_socket = evm->events[index].udata;
#endif

            (*evm_socket->callback)(evm_socket->closure);
        }

        // Dispatch timers
        if (evm->timer_list_count)
        {
            // Get the current time
            clock_gettime(CLOCK_MONOTONIC, &now);

            // Process any expired timers
            while (evm->timer_list_count && timespec_delta_millis(&now, &evm->timer_list[0].timespec) <= 0)
            {
                // Save the timer callback/closure
                timer_callback = evm->timer_list[0].callback;
                timer_closure = evm->timer_list[0].closure;

                // Remove the timer
                evm->timer_list_count -= 1;
                if (evm->timer_list_count)
                {
                    memmove(&evm->timer_list[0], &evm->timer_list[1], (evm->timer_list_count) * sizeof(timer_event_t));
                }

                // Invoke the callback
                (timer_callback)(timer_closure);
            }
        }
    }
}
