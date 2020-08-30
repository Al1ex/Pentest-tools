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

#ifndef ICMPTUNNEL_CONFIG_H
#define ICMPTUNNEL_CONFIG_H

/* program version. */
#define ICMPTUNNEL_VERSION "0.1-beta"

/* default timeout in seconds between keep-alive requests. */
#define ICMPTUNNEL_TIMEOUT 5

/* default number of retries before a connection is dropped. */
#define ICMPTUNNEL_RETRIES 5

/* default interval between punch-thru packets. */
#define ICMPTUNNEL_PUNCHTHRU_INTERVAL 1

/* default window size of punch-thru packets. */
#define ICMPTUNNEL_PUNCHTHRU_WINDOW 10

/* default tunnel mtu in bytes; assume the size of an ethernet frame. */
#define ICMPTUNNEL_MTU 1500

/* default to standard linux behaviour, do not emulate windows ping. */
#define ICMPTUNNEL_EMULATION 0

/* default to running in the foreground. */
#define ICMPTUNNEL_DAEMON 0

#endif
