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

#include <string.h>

#include "peer.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "protocol.h"
#include "server-handlers.h"

void handle_connection_request(struct echo_skt *skt, struct peer *client,
    struct echo *request, uint32_t sourceip)
{
    struct packet_header *header = (struct packet_header*)skt->data;
    memcpy(header->magic, PACKET_MAGIC, sizeof(struct packet_header));

    /* is a client already connected? */
    if (client->connected) {
        header->type = PACKET_SERVER_FULL;
    }
    else {
        header->type = PACKET_CONNECTION_ACCEPT;

        client->connected = 1;
        client->seconds = 0;
        client->timeouts = 0;
        client->nextpunchthru = 0;
        client->nextpunchthru_write = 0;
        client->linkip = sourceip;
    }

    /* send the response. */
    struct echo response;
    response.size = sizeof(struct packet_header);
    response.reply = 1;
    response.id = request->id;
    response.seq = request->seq;

    send_echo(skt, sourceip, &response);
}

/* handle a punch-thru packet. */
void handle_punchthru(struct peer *client, struct echo *request, uint32_t sourceip)
{
    if (!client->connected || sourceip != client->linkip)
        return;

    /* store the sequence number. */
    client->punchthru[client->nextpunchthru_write] = request->seq;
    client->nextpunchthru_write++;
    client->nextpunchthru_write %= ICMPTUNNEL_PUNCHTHRU_WINDOW;

    client->seconds = 0;
    client->timeouts = 0;
}

void handle_keep_alive_request(struct echo_skt *skt, struct peer *client, struct echo *request,
    uint32_t sourceip)
{
    if (!client->connected || sourceip != client->linkip)
        return;

    /* write a keep-alive response. */
    struct packet_header *header = (struct packet_header*)skt->data;
    memcpy(header->magic, PACKET_MAGIC, sizeof(header->magic));
    header->type = PACKET_KEEP_ALIVE;

    /* send the response to the client. */
    struct echo response;
    response.size = sizeof(struct packet_header);
    response.reply = 1;
    response.id = request->id;
    response.seq = request->seq;

    send_echo(skt, sourceip, &response);

    client->timeouts = 0;
}

void handle_server_data(struct echo_skt *skt, struct tun_device *device, struct peer *client,
    struct echo *request, uint32_t sourceip)
{
    if (!client->connected || sourceip != client->linkip)
        return;

    /* determine the size of the encapsulated frame. */
    int framesize = request->size - sizeof(struct packet_header);

    if (!framesize)
        return;

    /* write the frame to the tunnel interface. */
    write_tun_device(device, skt->data + sizeof(struct packet_header), framesize);

    /* save the icmp id and sequence numbers for any return traffic. */
    client->nextid = request->id;
    client->nextseq = request->seq;
    client->seconds = 0;
    client->timeouts = 0;
}
