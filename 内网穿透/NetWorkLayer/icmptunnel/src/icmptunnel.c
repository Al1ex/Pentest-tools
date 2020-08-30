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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "client.h"
#include "server.h"
#include "options.h"
#include "forwarder.h"

static void version()
{
    fprintf(stderr, "icmptunnel is version %s (built %s).\n", ICMPTUNNEL_VERSION, __DATE__);
    exit(0);
}

static void help(const char *program)
{
    fprintf(stderr, "icmptunnel %s.\n", ICMPTUNNEL_VERSION);
    fprintf(stderr, "usage: %s [options] -s|server\n\n", program);
    fprintf(stderr, "  -v               print version and exit.\n");
    fprintf(stderr, "  -h               print help and exit.\n");
    fprintf(stderr, "  -k <interval>    interval between keep-alive packets.\n");
    fprintf(stderr, "                   the default interval is %i seconds.\n", ICMPTUNNEL_TIMEOUT);
    fprintf(stderr, "  -r <retries>     packet retry limit before timing out.\n");
    fprintf(stderr, "                   the default is %i retries.\n", ICMPTUNNEL_RETRIES);
    fprintf(stderr, "  -m <mtu>         max frame size of the tunnel interface.\n");
    fprintf(stderr, "                   the default tunnel mtu is %i bytes.\n", ICMPTUNNEL_MTU);
    fprintf(stderr, "  -e               emulate the microsoft ping utility.\n");
    fprintf(stderr, "  -d               run in the background as a daemon.\n");
    fprintf(stderr, "  -s               run in server-mode.\n");
    fprintf(stderr, "  server           run in client-mode, using the server ip/hostname.\n\n");
    exit(0);
}

static void usage(const char *program)
{
    fprintf(stderr, "unknown or missing option -- '%c'\n", optopt);
    fprintf(stderr, "use %s -h for more information.\n", program);
    exit(1);
}

static void signalhandler(int sig)
{
    /* unused variable. */
    (void)sig;

    stop();
}

int main(int argc, char *argv[])
{
    char *program = argv[0];
    char *hostname = NULL;
    int servermode = 0;

    struct options options = {
        ICMPTUNNEL_TIMEOUT,
        ICMPTUNNEL_RETRIES,
        ICMPTUNNEL_MTU,
        ICMPTUNNEL_EMULATION,
        ICMPTUNNEL_DAEMON
    };

    /* parse the option arguments. */
    opterr = 0;
    int opt;
    while ((opt = getopt(argc, argv, "vhk:r:m:eds")) != -1) {
        switch (opt) {
        case 'v':
            version();
            break;
        case 'h':
            help(program);
            break;
        case 'k':
            options.keepalive = atoi(optarg);
            if (options.keepalive == 0) {
                options.keepalive = 1;
            }
            break;
        case 'r':
            if (strcmp(optarg, "infinite") == 0) {
                options.retries = -1;
            }
            else {
                options.retries = atoi(optarg);
            }
            break;
        case 'm':
            options.mtu = atoi(optarg);
            break;
        case 'e':
            options.emulation = 1;
            break;
        case 'd':
            options.daemon = 1;
            break;
        case 's':
            servermode = 1;
            break;
        case '?':
            /* fall-through. */
        default:
            usage(program);
            break;
        }
    }

    argc -= optind;
    argv += optind;

    /* if we're running in client mode, parse the server hostname. */
    if (!servermode) {
        if (argc < 1) {
            fprintf(stderr, "missing server ip/hostname.\n");
            fprintf(stderr, "use %s -h for more information.\n", program);
            return 1;
        }
        hostname = argv[0];

        argc--;
        argv++;
    }

    /* check for extraneous options. */
    if (argc > 0) {
        fprintf(stderr, "unknown option -- '%s'\n", argv[0]);
        fprintf(stderr, "use %s -h for more information.\n", program);
        return 1;
    }

    /* check for root privileges. */
    if (geteuid() != 0) {
        fprintf(stderr, "opening raw icmp sockets requires root privileges.\n");
        fprintf(stderr, "are you running as root?\n");
        exit(1);
    }

    /* register the signal handlers. */
    signal(SIGINT, signalhandler);
    signal(SIGTERM, signalhandler);

    srand(time(NULL));

    if (servermode) {
        /* run the server. */
        return server(&options);
    }

    /* run the client. */
    return client(hostname, &options);
}
