#!/usr/bin/env python

import os
import socket
import time
import select

(SUCCESS, COMMAND_FAIL, CONNECT_FAIL, DISCONNECT, ACCEPT_FAIL, DATA_MISMATCH) = range(6)
labels = ["success", "command fail", "connection fail", "disconnection", "accept fail", "data mismatch"]

def test(expect, client_af, server_af, from_ip, to_ip, args="", client_sends_first="NICK nick\r\n", server_receives="NICK nick\r\n", app_responds="", app_inserts="", server_sends_then=":localhost 001 nick :Welcome\r\n"):
    # Open and close a socket to get random port available

    client_sock = socket.socket(client_af, socket.SOCK_STREAM, 0)
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    client_sock.bind(('', 0))
    client_port = client_sock.getsockname()[1]
    client_sock.close()

    # Open a socket for mock server

    server_sock = socket.socket(server_af, socket.SOCK_STREAM, 0)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server_sock.bind(('', 0))
    server_sock.listen(0)
    server_port = server_sock.getsockname()[1]

    all_args = "-1 %s %d %s %d" % (args, client_port, to_ip, server_port)
    print "Running with %s" % all_args
    if os.system("./6tunnel " + all_args) != 0:
        if expect != COMMAND_FAIL:
            raise Exception("expected %s yet command failed" % labels[expect])
        else:
            return

    client_sock = socket.socket(client_af, socket.SOCK_STREAM, 0)

    # Give 6tunnel instance some time to initialize

    connected = False
    for i in range(10):
        try:
            client_sock.connect((from_ip, client_port))
        except socket.error:
            time.sleep(0.1)
        else:
            connected = True
            break

    if not connected:
        if expect != CONNECT_FAIL:
            raise Exception("expected %s yet connect failed" % labels[expect])
        else:
            return

    # Send first data

    client_sock.send(client_sends_first)

    # Wait for 6tunnel to connect to the server

    rlist, wlist, xlist = select.select([server_sock], [], [], 1)

    if not rlist:
        if expect != ACCEPT_FAIL:
            raise Exception("expected %s yet accept failed" % labels[expect])
        else:
            return

    accept_sock = server_sock.accept()[0]

    # Make sure that 6tunnel doesn't send anything to the client

    rlist, wlist, xlist = select.select([client_sock], [], [], 1)

    if rlist:
        try:
            res = client_sock.recv(1)
            if not res:
                raise socket.error
        except socket.error:
            if expect != DISCONNECT:
                raise Exception("expected %s yet disconnected" % labels[expect])
            else:
                return

        raise Exception("unexpected data sent to client")

    # Do the data exchange

    if app_responds:
        tmp = client_sock.recv(len(app_responds))
        if tmp != app_responds:
            raise Exception("expected 6tunnel response \"%s\" yet did not receive" % app_responds)

    if app_inserts:
        tmp = accept_sock.recv(len(app_inserts))
        if tmp != app_inserts:
            raise Exception("expected 6tunnel insert \"%s\" yet did not receive" % app_sends_first)

    if accept_sock.recv(len(server_receives)) != server_receives:
        raise Exception("data mismatch")

    accept_sock.send(server_sends_then)

    if client_sock.recv(len(server_sends_then)) != server_sends_then:
        raise Exception("data mismatch")

    accept_sock.close()
    server_sock.close()
    client_sock.close()

    if expect != SUCCESS:
        raise Exception("expected %d yet succeeded" % expect)

test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1')
test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-l 127.0.0.1')
test(COMMAND_FAIL, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-l ::1')
test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-s ::1')
test(COMMAND_FAIL, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-s 127.0.0.1')

test(SUCCESS, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4')
test(SUCCESS, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -l 127.0.0.1')
test(COMMAND_FAIL, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -l ::1')
test(SUCCESS, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -s 127.0.0.1')
test(COMMAND_FAIL, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -s ::1')

test(SUCCESS, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6')
test(SUCCESS, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -l ::1')
test(COMMAND_FAIL, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -l 127.0.0.1')
test(SUCCESS, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -s 127.0.0.1')
test(COMMAND_FAIL, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -s ::1')

test(SUCCESS, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6')
test(SUCCESS, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -l ::1')
test(COMMAND_FAIL, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -l 127.0.0.1')
test(SUCCESS, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -s ::1')
test(COMMAND_FAIL, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -s 127.0.0.1')

# Test IRC password options

test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-I password', app_inserts="PASS password\r\n")

test(ACCEPT_FAIL, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-i password', client_sends_first="NICK nick\r\n")

test(ACCEPT_FAIL, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-i password', client_sends_first="PASS invalid\r\nNICK nick\r\n", app_responds=":6tunnel 464 * :Password incorrect\r\n")

test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-i password', client_sends_first="PASS password\r\nNICK nick\r\n")

