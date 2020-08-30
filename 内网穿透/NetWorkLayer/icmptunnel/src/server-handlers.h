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

#ifndef ICMPTUNNEL_SERVER_HANDLERS_H
#define ICMPTUNNEL_SERVER_HANDLERS_H

struct peer;
struct echo;
struct echo_skt;

/* handle a connection request packet. */
void handle_connection_request(struct echo_skt *skt, struct peer *client, struct echo *request,
    uint32_t sourceip);

/* handle a punch-thru packet. */
void handle_punchthru(struct peer *client, struct echo *request, uint32_t sourceip);

/* handle a keep-alive request packet. */
void handle_keep_alive_request(struct echo_skt *skt, struct peer *client, struct echo *request,
    uint32_t sourceip);

/* handle a data packet. */
void handle_server_data(struct echo_skt *skt, struct tun_device *devuce, struct peer *client,
    struct echo *request, uint32_t sourceip);

#endif
