/*
 *  https://github.com/jamesbarlow/icmptunnel
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2016 James Barlow-Bignell
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include "checksum.h"

uint16_t checksum(const char *buf, int size)
{
    uint16_t *p = (uint16_t*)buf;
    uint32_t sum = 0;

    /* calculate the sum over the buffer in 2-byte words. */
    for (sum = 0; size > 1; size -= 2) {
        sum += *p++;
    }

    /* there may be a final byte to sum. */
    if (size == 1) {
        sum += *(unsigned char*)p;
    }

    /* sum the high and low 16 bits. */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}
