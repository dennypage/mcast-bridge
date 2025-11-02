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


#include <stdint.h>
#include <time.h>
#include <memory.h>

#include "common.h"



//
// Calculate the relative number of milliseconds between ts1 and ts2
//
long timespec_delta_millis(
    const struct timespec *     ts1,
    const struct timespec *     ts2)
{
    long                        sec;
    long                        nsec;

    sec = ts2->tv_sec - ts1->tv_sec;
    nsec =  ts2->tv_nsec - ts1->tv_nsec;
    if (nsec < 0)
    {
        sec -= 1;
        nsec += 1000000000L;
    }

    return sec * 1000L + nsec / 1000000L;
}


//
// Calculate an internet checksum
//
uint16_t inet_csum(
    const uint16_t *            addr,
    int                         len)
{
    uint32_t                    sum = 0;
    uint16_t                    answer;

    // Sum all 16-bit words
    while (len > 1)
    {
        sum += *addr++;
        len -= sizeof(*addr);
    }

    // Add the remaining byte, if any
    if (len == 1)
    {
        sum += *(uint8_t *) addr;
    }

    // Add carries from the upper 16 bits to the lower 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    // One's complement
    answer = (uint16_t) ~sum;

    return answer;
}


//
// Calculate an internet v6 checksum including 10 word psuedo header
//
uint16_t inet6_csum(
    const uint16_t *            addr,
    int                         len,
    const uint16_t *            src_addr,
    const uint16_t *            dst_addr,
    uint8_t                     next_header)
{
    uint32_t                    sum = 0;
    uint16_t                    answer;
    unsigned int                i;
    struct {
        uint32_t                length;
        uint8_t                 zero[3];
        uint8_t                 next_header;
    } psuedo_header;

    // First, the 16 half words of source and destination address
    for (i = 0; i < 8; i++)
    {
        sum += (src_addr)[i];
    }
    for (i = 0; i < 8; i++)
    {
        sum += (dst_addr)[i];
    }

    // Then, the remaining 4 half words of the psuedo header
    memset(&psuedo_header, 0, sizeof(psuedo_header));
    psuedo_header.length = htonl(len);
    psuedo_header.next_header = next_header;
    for (i = 0; i < 4; i++)
    {
        sum += ((uint16_t *)&psuedo_header)[i];
    }

    // Sum all 16-bit words
    while (len > 1)
    {
        sum += *addr++;
        len -= sizeof(*addr);
    }

    // Add the remaining byte, if any
    if (len == 1)
    {
        sum += *(uint8_t *) addr;
    }

    // Add carries from the upper 16 bits to the lower 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    // One's complement
    answer = (uint16_t) ~sum;

    return answer;
}


//
// Decode an 8-bit timecode value (IGMPv3 & MLDv2)
//
uint16_t timecode_8bit_decode(
    uint8_t                     code)
{
    uint16_t                    exponent;
    uint16_t                    mantissa;

    //   If the code is < 128, it directly represents the value
    //   If the code is >= 128, it represents a floating-point encoded like so:
    //      0 1 2 3 4 5 6 7
    //     +-+-+-+-+-+-+-+-+
    //     |1| exp | mant  |
    //     +-+-+-+-+-+-+-+-+
    //   and the value is (mant | 0x10) << (exp + 3)

    if (code < 128)
    {
        return(code);
    }

    exponent = ((code >> 4) & 0x07) + 3;
    mantissa = (code & 0x0f) | 0x10;
    return(mantissa << exponent);
}

// Decode an 16-bit timecode value (MLDv2)
uint32_t timecode_16bit_decode(
    uint16_t                     code)
{
    uint32_t                    exponent;
    uint32_t                    mantissa;

    //   If the code is < 32768, it directly represents the value
    //   If the code is >= 32768, it represents a floating-point encoded like so:
    //      0 1 2 3 4 5 6 7 8 9 A B C D E F
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |1| exp |          mant         |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   and the value is (mant | 0x1000) << (exp + 3)

    if (code < 32768)
    {
        return(code);
    }

    exponent = ((code >> 12) & 0x07) + 3;
    mantissa = (code & 0x0fff) | 0x1000;
    return(mantissa << exponent);
}


// Currently unused
#if 0
//
// Encode an 8-bit timecode value (IGMPv3 & MLDv2)
//
uint8_t timecode_8bit_encode(
    uint16_t                    value)
{
    uint16_t                    exponent;
    uint16_t                    mantissa;

    // Values below 128 are directly encoded
    if (value < 128) {
        return value;
    }

    // 31744 is the maximum encodable value
    if (value >= 31744)
    {
        return 0xff;
    }

    // Shift the value with a floor bias until it fits into 4 bits
    exponent = 0;
    mantissa = value >> 3;
    while (mantissa >= 32)
    {
        exponent += 1;
        mantissa >>= 1;
    }
    mantissa &= 0x0f;

    return (0x80 | (exponent << 4) | mantissa);
}


//
// Encode an 16-bit timecode value (MLDv2)
//
uint16_t timecode_16bit_encode(
    uint32_t                    value)
{
    uint32_t                    exponent;
    uint32_t                    mantissa;

    // Values below 32768 are directly encoded
    if (value < 32768) {
        return value;
    }

    // 31744 is the maximum encodable value
    if (value >= 8387584)
    {
        return 0xffff;
    }

    // Shift the value with a floor bias until it fits into 12 bits
    exponent = 0;
    mantissa = value >> 3;
    while (mantissa >= 8192)
    {
        exponent += 1;
        mantissa >>= 1;
    }
    mantissa &= 0x0fff;

    return (0x8000 | (exponent << 12) | mantissa);
}
#endif
