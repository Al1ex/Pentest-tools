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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "tun-device.h"

int open_tun_device(struct tun_device *device, int mtu)
{
    struct ifreq ifr;
    const char *clonedev = "/dev/net/tun";

    /* open the clone device. */
    if ((device->fd = open(clonedev, O_RDWR)) < 0) {
        fprintf(stderr, "unable to open %s: %s\n", clonedev, strerror(errno));
        fprintf(stderr, "is the tun kernel module loaded?\n");
        return 1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    /* try to create the device, the kernel will choose a name. */
    if (ioctl(device->fd, TUNSETIFF, &ifr) < 0) {
        fprintf(stderr, "unable to create a tunnel device: %s\n", strerror(errno));
        return 1;
    }

    /* copy out the device name and mtu. */
    strncpy(device->name, ifr.ifr_name, sizeof(device->name));
    device->mtu = mtu;

    fprintf(stderr, "opened tunnel device: %s\n", ifr.ifr_name);

    return 0;
}

int write_tun_device(struct tun_device *device, const char *buf, int size)
{
    /* write to the tunnel device. */
    if (write(device->fd, buf, size) != size) {
        fprintf(stderr, "unable to write to tunnel device: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}

int read_tun_device(struct tun_device *device, char *buf, int *size)
{
    /* read from the tunnel device. */
    if ((*size = read(device->fd, buf, device->mtu)) < 0) {
        fprintf(stderr, "unable to read from tunnel device: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}

void close_tun_device(struct tun_device *device)
{
    if (device->fd >= 0) {
        close(device->fd);
    }
}
