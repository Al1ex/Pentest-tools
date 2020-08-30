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

#include <stdio.h>
#include <string.h>

#include "config.h"
#include "options.h"
#include "client.h"
#include "peer.h"
#include "resolve.h"
#include "protocol.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "handlers.h"
#include "forwarder.h"
#include "client-handlers.h"

/* the server. */
static struct peer server;

/* program options. */
static struct options *opts;

/* handle an icmp packet. */
static void handle_icmp_packet(struct echo_skt *skt, struct tun_device *device);

/* handle data from the tunnel interface. */
static void handle_tunnel_data(struct echo_skt *skt, struct tun_device *device);

/* handle a timeout. */
static void handle_timeout(struct echo_skt *skt);

int client(const char *hostname, struct options *options)
{
    struct echo_skt skt;
    struct tun_device device;

    struct handlers handlers = {
        &handle_icmp_packet,
        &handle_tunnel_data,
        &handle_timeout
    };
    opts = options;

    /* calculate the required icmp payload size. */
    int bufsize = options->mtu + sizeof(struct packet_header);

    /* resolve the server hostname. */
    if (resolve(hostname, &server.linkip) != 0)
        return 1;

    /* open an echo socket. */
    if (open_echo_skt(&skt, bufsize) != 0)
        return 1;

    /* open a tunnel interface. */
    if (open_tun_device(&device, options->mtu) != 0)
        return 1;

    /* choose initial icmp id and sequence numbers. */
    server.nextid = rand();
    server.nextseq = rand();

    /* send the initial connection request. */
    send_connection_request(&skt, &server, opts->emulation);

    /* run the packet forwarding loop. */
    int ret = forward(&skt, &device, &handlers);

    close_tun_device(&device);
    close_echo_skt(&skt);

    return ret;
}

void handle_icmp_packet(struct echo_skt *skt, struct tun_device *device)
{
    struct echo echo;
    uint32_t sourceip;

    /* receive the packet. */
    if (receive_echo(skt, &sourceip, &echo) != 0)
        return;

    /* we're only expecting packets from the server. */
    if (sourceip != server.linkip)
        return;

    /* we're only expecting echo replies. */
    if (!echo.reply)
        return;

    /* check the packet size. */
    if (echo.size < (int)sizeof(struct packet_header))
        return;

    /* check the header magic. */
    struct packet_header *header = (struct packet_header*)skt->data;

    if (memcmp(header->magic, PACKET_MAGIC, sizeof(header->magic)) != 0)
        return;

    switch (header->type) {
    case PACKET_CONNECTION_ACCEPT:
        /* handle a connection accept packet. */
        handle_connection_accept(skt, &server, opts);
        break;

    case PACKET_SERVER_FULL:
        /* handle a server full packet. */
        handle_server_full(&server);
        break;

    case PACKET_DATA:
        /* handle a data packet. */
        handle_client_data(skt, device, &server, &echo);
        break;

    case PACKET_KEEP_ALIVE:
        /* handle a keep-alive packet. */
        handle_keep_alive_response(&server);
        break;
    }
}

void handle_tunnel_data(struct echo_skt *skt, struct tun_device *device)
{
    int size;

    /* read the frame. */
    if (read_tun_device(device, skt->data + sizeof(struct packet_header), &size) != 0)
        return;

    /* if we're not connected then drop the frame. */
    if (!server.connected)
        return;

    /* write a data packet. */
    struct packet_header *header = (struct packet_header*)skt->data;
    memcpy(header->magic, PACKET_MAGIC, sizeof(header->magic));
    header->type = PACKET_DATA;

    /* send the encapsulated frame to the server. */
    struct echo echo;
    echo.size = sizeof(struct packet_header) + size;
    echo.reply = 0;
    echo.id = server.nextid;
    echo.seq = opts->emulation ? server.nextseq : server.nextseq++;

    send_echo(skt, server.linkip, &echo);
}

void handle_timeout(struct echo_skt *skt)
{
    /* send a punch-thru packet. */
    send_punchthru(skt, &server, opts->emulation);

    /* has the peer timeout elapsed? */
    if (++server.seconds == opts->keepalive) {
        server.seconds = 0;

        /* have we reached the max number of retries? */
        if (opts->retries != -1 && ++server.timeouts == opts->retries) {
            fprintf(stderr, "connection timed out.\n");

            /* stop the packet forwarding loop. */
            stop();
            return;
        }

        /* if we're still connecting, resend the connection request. */
        if (!server.connected) {
            send_connection_request(skt, &server, opts->emulation);
            return;
        }

        /* otherwise, send a keep-alive request. */
        send_keep_alive(skt, &server, opts->emulation);
    }
}
