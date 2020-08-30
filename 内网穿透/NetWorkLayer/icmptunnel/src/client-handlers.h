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

#ifndef ICMPTUNNEL_CLIENT_HANDLERS_H
#define ICMPTUNNEL_CLIENT_HANDLERS_H

struct peer;
struct options;
struct echo_skt;
struct tun_device;

/* send a connection request to the server. */
void send_connection_request(struct echo_skt *skt, struct peer *server, int emulation);

/* send a punchthru packet. */
void send_punchthru(struct echo_skt *skt, struct peer *server, int emulation);

/* send a keep-alive request to the server. */
void send_keep_alive(struct echo_skt *skt, struct peer *server, int emulation);

/* handle a connection accept packet. */
void handle_connection_accept(struct echo_skt *skt, struct peer *server, struct options *opts);

/* handle a server full packet. */
void handle_server_full(struct peer *server);

/* handle a data packet. */
void handle_client_data(struct echo_skt *skt, struct tun_device *device, struct peer *server,
    struct echo *echo);

/* handle a keep-alive packet. */
void handle_keep_alive_response(struct peer *server);

#endif
