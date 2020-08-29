/*
 *  6tunnel v0.13
 *  (C) Copyright 2000-2005,2013,2016,2019 by Wojtek Kaniewski <wojtekka@toxygen.net>
 *
 *  Contributions by:
 *  - Dariusz Jackowski <ascent@linux.pl>
 *  - Ramunas Lukosevicius <lukoramu@parok.lt>
 *  - Roland Stigge <stigge@antcom.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License Version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <time.h>

#define debug(x...) do { \
	if (verbose) \
		printf(x); \
} while(0)

int verbose = 0, conn_count = 0;
int remote_port, verbose, hexdump = 0;
int remote_hint[2] = { AF_INET6, AF_INET };
int local_hint = AF_INET;
char *remote_host, *irc_pass = NULL;
char *irc_send_pass = NULL;
char *pid_file = NULL;
const char *source_host;

typedef struct source_map {
	char *ipv4;
	char *ipv6;
	struct source_map *next;
} source_map_t;

source_map_t *source_map = NULL;
char *source_map_file = NULL;

char *xmalloc(int size)
{
	char *tmp;

	tmp = malloc(size);

	if (tmp == NULL) {
		perror("malloc");
		exit(1);
	}

	return tmp;
}

char *xrealloc(char *ptr, int size)
{
	char *tmp;

	tmp = realloc(ptr, size);

	if (tmp == NULL) {
		perror("realloc");
		exit(1);
	}

	return tmp;
}

char *xstrdup(const char *str)
{
	char *tmp;

	tmp = strdup(str);

	if (tmp == NULL) {
		perror("strdup");
		exit(1);
	}

	return tmp;
}

char *xntop(const struct sockaddr *sa)
{
	char *tmp = NULL;

	if (sa->sa_family == AF_INET)
	{
		struct sockaddr_in *sin = (struct sockaddr_in*) sa;

		tmp = xmalloc(INET_ADDRSTRLEN);

		if (inet_ntop(sa->sa_family, &sin->sin_addr, tmp, INET_ADDRSTRLEN) == NULL)
		{
			free(tmp);
			tmp = NULL;
		}
	}
	else if (sa->sa_family == AF_INET6)
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*) sa;
		tmp = xmalloc(INET6_ADDRSTRLEN);

		if (inet_ntop(sa->sa_family, &sin6->sin6_addr, tmp, INET6_ADDRSTRLEN) == NULL)
		{
			free(tmp);
			tmp = NULL;
		}
	}

	return tmp;
}

struct addrinfo *resolve_host(const char *name, int port, int hint)
{
	struct addrinfo *result = NULL;
	struct addrinfo hints;
	char port_str[16];
	int rc;

	snprintf(port_str, sizeof(port_str), "%u", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = hint;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (name == NULL && port != 0) ? AI_PASSIVE : 0;

	rc = getaddrinfo(name, (port != 0) ? port_str : NULL, &hints, &result);

	if (rc == 0)
		return result;

	debug("resolver %s port %d hint %d failed: %s\n", name, port, hint, gai_strerror(rc));

	return NULL;
}

void print_hexdump(const char *buf, int len)
{
	int i, j;

	for (i = 0; i < ((len / 16) + ((len % 16) ? 1 : 0)); i++) {
		printf("%.4x: ", i * 16);

		for (j = 0; j < 16; j++) {
			if (i * 16 + j < len)
				printf("%.2x ", buf[i*16+j]);
			else
				printf("   ");
			if (j == 7)
				printf(" ");
		}

		printf(" ");

		for (j = 0; j < 16; j++) {
			if (i * 16 + j < len) {
				char ch = buf[i * 16 + j];

				printf("%c", (isprint(ch)) ? ch : '.');
			}
		}

		printf("\n");
	}
}

const char *source_map_find(const char *ipv4)
{
	source_map_t *m;

	for (m = source_map; m != NULL; m = m->next) {
		if (strcmp(m->ipv4, ipv4) == 0)
			return m->ipv6;
	}

	for (m = source_map; m != NULL; m = m->next) {
		if ((strcmp(m->ipv4, "0.0.0.0") == 0) || (strcmp(m->ipv4, "default") == 0))
			return m->ipv6;
	}

	return source_host;
}

void make_tunnel(int rsock, const char *client_addr)
{
	char buf[4096], *outbuf = NULL, *inbuf = NULL;
	int sock = -1, outlen = 0, inlen = 0;
	struct sockaddr *sa = NULL;
	const char *source;
	struct addrinfo *connect_ai = NULL;
	struct addrinfo *bind_ai = NULL;
	struct addrinfo *ai_ptr;
	int source_hint;

	if (source_map != NULL) {
		source = source_map_find(client_addr);

		if (source == NULL) {
			debug("<%d> connection from unmapped address (%s), disconnecting\n", rsock, client_addr);
			goto cleanup;
		}

		debug("<%d> mapped to %s\n", rsock, source);
	} else
		source = source_host;

	if (irc_pass != NULL) {
		int i, ret;

		for (i = 0; i < sizeof(buf) - 1; i++) {
			if ((ret = read(rsock, buf + i, 1)) < 1)
				goto cleanup;
			if (buf[i] == '\n')
				break;
		}

		buf[i] = 0;

		if (i > 0 && buf[i - 1] == '\r')
			buf[i - 1] = 0;

		if (i == 4095 || strncasecmp(buf, "PASS ", 5) != 0) {
			char *tmp;

			debug("<%d> irc proxy auth failed - junk\n", rsock);

			tmp = "ERROR :Closing link: Make your client send password first\r\n";
			if (write(rsock, tmp, strlen(tmp)) != strlen(tmp)) {
				// Do nothing. We're failing anyway.
			}

			goto cleanup;
		}

		if (strcmp(buf + 5, irc_pass) != 0) {
			char *tmp;

			debug("<%d> irc proxy auth failed - password incorrect\n", rsock);
			tmp = ":6tunnel 464 * :Password incorrect\r\nERROR :Closing link: Password incorrect\r\n";
			if (write(rsock, tmp, strlen(tmp)) != strlen(tmp)) {
				// Do nothing. We're failing anyway.
			}

			goto cleanup;
		}

		debug("<%d> irc proxy auth succeeded\n", rsock);
	}

	connect_ai = resolve_host(remote_host, remote_port, remote_hint[0]);

	if (connect_ai == NULL) {
		connect_ai = resolve_host(remote_host, remote_port, remote_hint[1]);

		if (connect_ai == NULL) {
			debug("<%d> unable to resolve %s,%d\n", rsock, remote_host, remote_port);
			goto cleanup;
		}

		source_hint = remote_hint[1];
	} else {
		source_hint = remote_hint[0];
	}

	for (ai_ptr = connect_ai; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		sock = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, 0);

		if (sock == -1) {
			if (ai_ptr->ai_next != NULL)
				continue;
			debug("<%d> unable to create socket (%s)\n", rsock, strerror(errno));
			goto cleanup;
		}

		if (source != NULL)
		{
			bind_ai = resolve_host(source, 0, source_hint);

			if (bind_ai == NULL) {
				debug("<%d> unable to resolve source host (%s)\n", rsock, (source != NULL) ? source : "default");
				goto cleanup;
			}

			if (bind(sock, bind_ai->ai_addr, bind_ai->ai_addrlen) == -1) {
				if (ai_ptr->ai_next != NULL) {
					close(sock);
					sock = -1;
					continue;
				}
				debug("<%d> unable to bind to source host (%s)\n", rsock, (source != NULL) ? source : "default");
				goto cleanup;
			}

			freeaddrinfo(bind_ai);
			bind_ai = NULL;
		}

		if (connect(sock, ai_ptr->ai_addr, ai_ptr->ai_addrlen) != -1)
			break;

		if (ai_ptr->ai_next == NULL) {
			debug("<%d> connection failed (%s,%d)\n", rsock, remote_host, remote_port);
			goto cleanup;
		}

		close(sock);
		sock = -1;
	}

	freeaddrinfo(connect_ai);
	connect_ai = NULL;

	debug("<%d> connected to %s,%d\n", rsock, remote_host, remote_port);

	if (irc_send_pass != NULL) {
		snprintf(buf, sizeof(buf), "PASS %s\r\n", irc_send_pass);
		if (write(sock, buf, strlen(buf)) != strlen(buf))
			goto cleanup;
	}

	for (;;) {
		fd_set rds, wds;
		int ret, sent;

		FD_ZERO(&rds);
		FD_SET(sock, &rds);
		FD_SET(rsock, &rds);

		FD_ZERO(&wds);
		if (outbuf && outlen)
			FD_SET(rsock, &wds);
		if (inbuf && inlen)
			FD_SET(sock, &wds);

		ret = select((sock > rsock) ? (sock + 1) : (rsock + 1), &rds, &wds, NULL, NULL);

		if (FD_ISSET(rsock, &wds)) {
			sent = write(rsock, outbuf, outlen);

			if (sent < 1)
				goto cleanup;

			if (sent == outlen) {
				free(outbuf);
				outbuf = NULL;
				outlen = 0;
			} else {
				memmove(outbuf, outbuf + sent, outlen - sent);
				outlen -= sent;
			}
		}

		if (FD_ISSET(sock, &wds)) {
			sent = write(sock, inbuf, inlen);

			if (sent < 1)
				goto cleanup;

			if (sent == inlen) {
				free(inbuf);
				inbuf = NULL;
				inlen = 0;
			} else {
				memmove(inbuf, inbuf + sent, inlen - sent);
				inlen -= sent;
			}
		}

		if (FD_ISSET(sock, &rds)) {
			if ((ret = read(sock, buf, sizeof(buf))) < 1)
				goto cleanup;

			if (hexdump) {
				printf("<%d> recvfrom %s,%d\n", rsock, remote_host, remote_port);
				print_hexdump(buf, ret);
			}

			sent = write(rsock, buf, ret);

			if (sent < 1)
				goto cleanup;

			if (sent < ret) {
				outbuf = xrealloc(outbuf, outlen + ret - sent);
				memcpy(outbuf + outlen, buf + sent, ret - sent);
				outlen = ret - sent;
			}
		}

		if (FD_ISSET(rsock, &rds)) {
			if ((ret = read(rsock, buf, sizeof(buf))) < 1)
				goto cleanup;

			if (hexdump) {
				printf("<%d> sendto %s,%d\n", rsock, remote_host, remote_port);
				print_hexdump(buf, ret);
			}

			sent = write(sock, buf, ret);

			if (sent < 1)
				goto cleanup;

			if (sent < ret) {
				inbuf = xrealloc(inbuf, inlen + ret - sent);
				memcpy(inbuf + inlen, buf + sent, ret - sent);
				inlen = ret - sent;
			}
		}
	}

cleanup:
	if (connect_ai != NULL)
		freeaddrinfo(connect_ai);

	if (bind_ai != NULL)
		freeaddrinfo(bind_ai);

	close(rsock);

	if (sock != -1)
		close(sock);
}

void usage(const char *arg0)
{
	fprintf(stderr,

"usage: %s [-146dvh] [-s sourcehost] [-l localhost] [-i pass]\n"
"           [-I pass] [-L limit] [-A filename] [-p pidfile]\n"
"           [-m mapfile] localport remotehost [remoteport]\n"
"\n"
"  -1  allow only single connection and quit\n"
"  -4  connect to IPv4 endpoints (default: connect to IPv6)\n"
"  -6  bind to IPv6 address (default: bind to IPv4)\n"
"  -d  don't detach\n"
"  -f  force tunneling (even if remotehost isn't resolvable)\n"
"  -h  print hex dump of packets\n"
"  -u  change UID and GID after bind()\n"
"  -i  act like irc proxy and ask for password\n"
"  -I  send specified password to the irc server\n"
"  -l  bind to specified address\n"
"  -L  limit simultaneous connections\n"
"  -p  write down pid to specified file\n"
"  -s  connect using specified address\n"
"  -m  read specified IPv4-to-IPv6 map file\n"
"  -v  be verbose\n"
"\n", arg0);
}

void clear_argv(char *argv)
{
	int x;

	for (x = 0; x < strlen(argv); x++)
		argv[x] = 'x';

	return;
}

void source_map_destroy(void)
{
	source_map_t *m;

	debug("source_map_destroy()\n");

	for (m = source_map; m != NULL; ) {
		source_map_t *n;

		free(m->ipv4);
		free(m->ipv6);
		n = m;
		m = m->next;
		free(n);
	}

	source_map = NULL;
}

void map_read(void)
{
	char buf[256];
	FILE *f;

	debug("reading map from %s\n", source_map_file);

	f = fopen(source_map_file, "r");

	if (f == NULL) {
		debug("unable to read map file, ignoring\n");
		return;
	}

	while (fgets(buf, sizeof(buf), f) != NULL) {
		char *p, *ipv4, *ipv6;
		source_map_t *m;

		for (p = buf; *p == ' ' || *p == '\t'; p++);

		if (!*p)
			continue;

		ipv4 = p;

		for (; *p && *p != ' ' && *p != '\t'; p++);

		if (!*p)
			continue;

		*p = 0;
		p++;

		for (; *p == ' ' || *p == '\t'; p++);

		if (!*p)
			continue;

		ipv6 = p;

		for (; *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n'; p++);

		*p = 0;

		debug("[%s] mapped to [%s]\n", ipv4, ipv6);

		m = (source_map_t*) xmalloc(sizeof(source_map_t));
		m->ipv4 = xstrdup(ipv4);
		m->ipv6 = xstrdup(ipv6);
		m->next = source_map;
		source_map = m;
	}

	fclose(f);
}

void sighup()
{
	source_map_destroy();
	map_read();

	signal(SIGHUP, sighup);
}

void sigchld()
{
	while (waitpid(-1, NULL, WNOHANG) > 0) {
		debug("child process exited\n");
		conn_count--;
	}

	signal(SIGCHLD, sigchld);
}

void sigterm()
{
	if (pid_file != NULL)
		unlink(pid_file);

	exit(0);
}

int main(int argc, char **argv)
{
	int force = 0, listen_fd, single_connection = 0, jeden = 1, local_port;
	int detach = 1, sa_len, conn_limit = 0, optc;
	const char *username = NULL;
	char *local_host = NULL;
	struct addrinfo *ai;
	struct addrinfo *ai_ptr;
	struct sockaddr *sa;
	struct sockaddr_in laddr;
	struct sockaddr_in6 laddr6;
	struct passwd *pw = NULL;
	char *tmp;
	int source_hint;

	while ((optc = getopt(argc, argv, "1dv46fHs:l:I:i:hu:m:L:A:p:")) != -1) {
		switch (optc) {
			case '1':
				single_connection = 1;
				break;
			case 'd':
				detach = 0;
				break;
			case 'v':
				verbose = 1;
				break;
			case '4':
				remote_hint[0] = AF_INET;
				remote_hint[1] = AF_INET6;
				break;
			case '6':
				local_hint = AF_INET6;
				break;
			case 's':
				source_host = optarg;
				break;
			case 'l':
				local_host = optarg;
				break;
			case 'f':
				force = 1;
				break;
			case 'i':
				irc_pass = xstrdup(optarg);
				clear_argv(argv[optind - 1]);
				break;
			case 'I':
				irc_send_pass = xstrdup(optarg);
				clear_argv(argv[optind - 1]);
				break;
			case 'h':
				hexdump = 1;
				break;
			case 'u':
				username = optarg;
				break;
			case 'm':
				source_map_file = optarg;
				break;
			case 'L':
				conn_limit = atoi(optarg);
				break;
			case 'p':
				pid_file = optarg;
				break;
			case 'H':
				fprintf(stderr, "%s: warning: -H is deprecated, please use proper combination of -4 and -6.\n", argv[0]);
				break;
			default:
				return 1;
		}
	}

	if (hexdump)
		verbose = 1;

	if (verbose)
		detach = 0;

	if (detach)
		verbose = 0;

	if (argc - optind < 2) {
		usage(argv[0]);
		exit(1);
	}

	if (username != NULL) {
		pw = getpwnam(username);

		if (pw == NULL) {
			fprintf(stderr, "%s: unknown user %s\n", argv[0], username);
			exit(1);
		}
	}

	if (source_map_file != NULL)
		map_read();

	local_port = atoi(argv[optind++]);
	remote_host = argv[optind++];
	remote_port = (argc == optind) ? local_port : atoi(argv[optind]);

	/* Check if destination and source hosts are resolvable. If it's expected to be
	 * available later, -f can be used. */

	debug("resolving %s\n", remote_host);

	ai = resolve_host(remote_host, remote_port, remote_hint[0]);

	if (ai == NULL) {
		ai = resolve_host(remote_host, remote_port, remote_hint[1]);

		if (ai == NULL && !force) {
			fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
			exit(1);
		}

		source_hint = remote_hint[1];
	} else {
		source_hint = remote_hint[0];
	}

	if (ai != NULL) {

		if (source_hint == AF_INET && local_hint == AF_INET)
			fprintf(stderr, "%s: warning: both local and remote addresses are IPv4\n", argv[0]);

		if (source_hint == AF_INET6 && local_hint == AF_INET6)
			fprintf(stderr, "%s: warning: both local and remote addresses are IPv6\n", argv[0]);

		tmp = xntop(ai->ai_addr);
		debug("resolved to %s\n", tmp);
		free(tmp);

		freeaddrinfo(ai);
	}

	if (source_host != NULL) {
		debug("resolving %s\n", source_host);

		ai = resolve_host(source_host, 0, source_hint);

		if (ai == NULL && !force) {
			fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], source_host);
			exit(1);
		}

		tmp = xntop(ai->ai_addr);
		debug("resolved to %s\n", tmp);
		free(tmp);

		freeaddrinfo(ai);
	}

	/* Resolve local address for bind(). In case of NULL address resolve_host() will
	 * return INADDR_ANY or in6addr_any, so we can bind either way. */

	debug("resolving local address %s\n", (local_host != NULL) ? local_host : "default");

	ai = resolve_host(local_host, local_port, local_hint);

	if (ai == NULL) {
		fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], local_host);
		exit(1);
	}

	tmp = xntop(ai->ai_addr);
	debug("resolved to %s\n", tmp);
	free(tmp);

	/* Now that we know that hosts are resolvable, dump some debugging information. */

	debug("local: %s,%d; ", (local_host != NULL) ? local_host : "default", local_port);
	debug("remote: %s,%d; ", remote_host, remote_port);

	if (source_map != NULL)
		debug("source: mapped\n");
	else
		debug("source: %s\n", (source_host != NULL) ? source_host : "default");

	/* Now bind. */

	listen_fd = socket(ai->ai_family, ai->ai_socktype, 0);

	if (listen_fd == -1) {
		perror("socket");
		exit(1);
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &jeden, sizeof(jeden)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	for (ai_ptr = ai; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		if (bind(listen_fd, ai_ptr->ai_addr, ai_ptr->ai_addrlen) == -1 && ai_ptr->ai_next == NULL) {
			perror("bind");
			exit(1);
		}
	}

	if (listen(listen_fd, 100) == -1) {
		perror("listen");
		exit(1);
	}

	freeaddrinfo(ai);
	ai = NULL;

	/* Daemonize. */

	if (detach) {
		int i, ret;

		signal(SIGHUP, sighup);

		for (i = 0; i < 3; i++)
			close(i);

		ret = fork();

		if (ret == -1) {
			perror("fork");
			exit(1);
		}

		if (ret)
			exit(0);
	}

	/* Store process id if requested. */

	if (pid_file != NULL) {
		FILE *f = fopen(pid_file, "w");

		if (!f)
			debug("warning: cannot write to pidfile (%s)\n", strerror(errno));
		else {
			fprintf(f, "%d", getpid());
			fclose(f);
		}
	}

	/* Change user and group id if requested. */

	if (pw != NULL) {
		if ((setgid(pw->pw_gid) == -1) || (setuid(pw->pw_uid) == -1)) {
			perror("setuid/setgid");
			exit(1);
		}
	}

	setsid();
	signal(SIGCHLD, sigchld);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);
	signal(SIGHUP, sighup);

	for (;;) {
		int ret;
		fd_set rds;
		int client_fd;
		char *client_addr;
		int client_port;
		struct sockaddr sa;
		unsigned int sa_len = sizeof(sa);

		FD_ZERO(&rds);
		FD_SET(listen_fd, &rds);

		if (select(listen_fd + 1, &rds, NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;

			perror("select");
			break;
		}

		client_fd = accept(listen_fd, &sa, &sa_len);

		if (client_fd == -1) {
			perror("accept");
			break;
		}

		client_addr = xntop(&sa);

		client_port = (sa.sa_family == AF_INET) ? ((struct sockaddr_in*) &sa)->sin_port :
			((struct sockaddr_in6*) &sa)->sin6_port;

		debug("<%d> connection from %s,%d", client_fd, client_addr, ntohs(client_port));

		if (conn_limit && (conn_count >= conn_limit)) {
			debug(" -- rejected due to limit.\n");
			shutdown(client_fd, 2);
			close(client_fd);
			continue;
		}

		if (conn_limit) {
			conn_count++;
			debug(" (no. %d)", conn_count);
		}

		fflush(stdout);

		if ((ret = fork()) == -1) {
			debug(" -- fork() failed.\n");
			shutdown(client_fd, 2);
			close(client_fd);
			free(client_addr);
			continue;
		}

		if (!ret) {
			signal(SIGHUP, SIG_IGN);
			close(listen_fd);
			debug("\n");
			make_tunnel(client_fd, client_addr);
			free(client_addr);
			debug("<%d> connection closed\n", client_fd);
			exit(0);
		}

		close(client_fd);
		free(client_addr);

		if (single_connection) {
			shutdown(listen_fd, 2);
			close(listen_fd);
			exit(0);
		}

	}

	close(listen_fd);

	exit(1);
}
