/*
Background:
===========
This program is a fork of 'hwfwpass' (https://github.com/MRGEffitas/hwfwbypass) and simply proposes a slight modification in
the way it runs. I made this fork to fit my specific needs which required a slight rewriting of the initial hwfwpass code.

DivertTCPconn relies on the windivert library (https://reqrypt.org/windivert.html) and must be run with administrator rights
on a Windows system of any kind.

What 'divertTCPconn' does:
==========================
DivertTCPconn captures incoming network traffic and based on the TCP destination port, diverts the traffic to another local TCP port.

[WARNING]: divertTCPconn only works on TCP connection.

Example: To divert incoming traffic initially aimed at port TCP-80 to another TCP port, for instance 8080:

	c:\> divertTCPconn 80 8080

In which circumstances can it be useful:
========================================
I found this trick to be useful in two situations:
1. 	When a local firewall blocks traffic to TCP port (eg: 445), divertTCPconn captures traffic before it reaches the local firewall
	and can then be redirected to another local port of your choice
2.	When a local service is already running on the local machine and is listening on a port you want to use (because, say it's the
	only port opened through another firewall you need to pass traffic through),divertTCPconn captures the traffic before the actual
	service and can then be redirected to another local port of your choice
3.	To screw things up like redirecting SSH or RDP traffic to a dumb port :-)
*/
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "stdafx.h"
#include "windivert.h"

#define MAXBUF  0xFFFF
#define INVALID 0

/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;

typedef struct
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;



/*
* Prototypes.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet);
static void PacketIpTcpInit(PTCPPACKET packet);
static void PacketInit(PPACKET packet);
static void DebugPrint(PVOID payload, PDATAPACKET divert, PTCPPACKET pack, HANDLE console, UINT payload_len, UINT i, UINT packet_len,
	WINDIVERT_ADDRESS addr, unsigned char packet[MAXBUF]);
static void DebugPrintPacket1(PTCPPACKET pack, HANDLE console);
static void DebugPrintPacket2(PTCPPACKET pack, HANDLE console, WINDIVERT_ADDRESS addr,
	PWINDIVERT_IPHDR ip_header, UINT i, PWINDIVERT_TCPHDR tcp_header, UINT packet_len, unsigned char packet[MAXBUF]);

/*
* Program entry point
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle, console;
	UINT i = 0;
	int j;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT32 orig_client_ip = 0;
	UINT32 orig_server_ip = 0;
	UINT32 orig_client_tcpSrcPort = 0;
	PVOID payload;
	UINT payload_len;
	PDATAPACKET divert = 0;
	UINT16 divert_len;
	TCPPACKET pack0;
	PTCPPACKET pack = &pack0;
	BOOLEAN debug;
	BOOLEAN disablechecksum;
	char filter[210];
	int cx;

	debug = FALSE;
	disablechecksum = FALSE;

	// Check arguments.
	switch (argc)
	{

	case 3:
		break;

	case 4:
		if (strcmp(argv[3], "disablechecksum") == 0) {
			disablechecksum = TRUE;
		}
		else if (strcmp(argv[3], "debug") == 0) {
			debug = TRUE;
		}
		break;

	case 5:
		if (strcmp(argv[3], "disablechecksum") == 0) {
			disablechecksum = TRUE;
		}

		else if (strcmp(argv[3], "debug") == 0) {
			debug = TRUE;
		}

		if (strcmp(argv[4], "disablechecksum") == 0) {
			disablechecksum = TRUE;
		}
		else if (strcmp(argv[4], "debug") == 0) {
			debug = TRUE;
		}
		break;

	default:
		fprintf(stderr, "Usage: %s original_dstport new_dstport [disablechecksum] [debug]\n",
			argv[0]);
		fprintf(stderr, "Examples:\n");
		fprintf(stderr, "\t%s 3389 31337 \n", argv[0]);
		fprintf(stderr, "\t%s 3389 31337 disablechecksum debug\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	// Get console handle for pretty colors.
	console = GetStdHandle(STD_OUTPUT_HANDLE);

	// Divert traffic matching the filter:
	cx = sprintf_s(filter, sizeof(filter),
		"((inbound and tcp.DstPort == %s )"
		" or (outbound and tcp.SrcPort == %s ))",
		argv[1], argv[2]);

	// Display current WinDivert filter
	if (debug) {
		for (j = 1; j < argc; j++) {
			printf("\n[DEBUG] arg%d=%s", j, argv[j]);
		}
		printf("\n[DEBUG] Used filter: %s\n", filter);
	}

	// Get a WinDivert handle
	handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);

	// If handle is not valid
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "[ERROR] filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "[ERROR] failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Max-out the packet queue:
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192))
	{
		fprintf(stderr, "[ERROR] failed to set packet queue length (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048))
	{
		fprintf(stderr, "[ERROR] failed to set packet queue time (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "[WARNING] failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		// Print info about the matching packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, &payload, &payload_len);

		if (ip_header == NULL && ipv6_header == NULL)
		{
			fprintf(stderr, "[WARNING] junk packet\n");
		}

		// show content of original packets
		if (debug) {
			printf("[DEBUG] Original packets:\n\t");
			DebugPrint(payload, divert, pack, console, payload_len, i, packet_len, addr, packet);
		}

		// save SRC and DST IP for further use
		if (tcp_header->Syn && !tcp_header->Ack)
		{
			orig_client_ip = ip_header->SrcAddr;
			orig_server_ip = ip_header->DstAddr;
			orig_client_tcpSrcPort = tcp_header->SrcPort;

			if (debug) {
				printf("%s", "[DEBUG] This is a SYN packet, storing src and dst ip.\n");
			}
		}

		// packet without data
		if (payload == NULL) {
			PacketIpTcpInit(pack);
			pack->ip.SrcAddr = ip_header->SrcAddr;
			pack->ip.DstAddr = ip_header->DstAddr;
			pack->ip.TTL = ip_header->TTL;
			pack->ip.Protocol = ip_header->Protocol;
			pack->ip.Version = ip_header->Version;
			pack->ip.TOS = ip_header->TOS;
			pack->ip.Id = ip_header->Id;
			pack->ip.FragOff0 = ip_header->FragOff0;
			pack->ip.HdrLength = ip_header->HdrLength;
			pack->ip.Length = ip_header->Length;
			pack->ip.Checksum = ip_header->Checksum;

			//when traffic from client to backdoor server
			if (ntohs(tcp_header->DstPort) == atoi(argv[1]))
			{
				pack->tcp.SrcPort = tcp_header->SrcPort;
				pack->tcp.DstPort = htons(atoi(argv[2]));
			}

			//when traffic from backdoor server to client
			if (ntohs(tcp_header->SrcPort) == atoi(argv[2]) && tcp_header->DstPort == orig_client_tcpSrcPort)
			{
				pack->tcp.SrcPort = htons(atoi(argv[1]));
				pack->tcp.DstPort = orig_client_tcpSrcPort;

				pack->ip.SrcAddr = orig_server_ip;
				pack->ip.DstAddr = orig_client_ip;
			}

			pack->tcp.SeqNum = tcp_header->SeqNum;
			pack->tcp.AckNum = tcp_header->AckNum;
			pack->tcp.HdrLength = tcp_header->HdrLength;
			pack->tcp.Fin = tcp_header->Fin;
			pack->tcp.Ack = tcp_header->Ack;
			pack->tcp.Rst = tcp_header->Rst;
			pack->tcp.Syn = tcp_header->Syn;
			pack->tcp.Psh = tcp_header->Psh;
			pack->tcp.Urg = tcp_header->Urg;
			pack->tcp.Window = tcp_header->Window;
			pack->tcp.Reserved1 = tcp_header->Reserved1;
			pack->tcp.Reserved2 = tcp_header->Reserved2;
			pack->tcp.Checksum = tcp_header->Checksum;

			if (!disablechecksum) {
				WinDivertHelperCalcChecksums((PVOID)pack, packet_len, 0);
			}

		}

		// packet with data
		else {
			// calculate size
			divert_len = sizeof(DATAPACKET) + (UINT16)payload_len;
			// allocate memory for packet
			divert = (PDATAPACKET)calloc(1, divert_len);
			if (divert == NULL)
			{
				fprintf(stderr, "[ERROR] memory allocation failed\n");
				exit(EXIT_FAILURE);
			}
			PacketInit(&divert->header);

			divert->header.ip.SrcAddr = ip_header->SrcAddr;
			divert->header.ip.DstAddr = ip_header->DstAddr;
			divert->header.ip.TTL = ip_header->TTL;
			divert->header.ip.Protocol = ip_header->Protocol;
			divert->header.ip.Version = ip_header->Version;
			divert->header.ip.TOS = ip_header->TOS;
			divert->header.ip.Length = htons(divert_len);
			divert->header.ip.HdrLength = ip_header->HdrLength;
			divert->header.ip.Id = ip_header->Id;
			divert->header.ip.FragOff0 = ip_header->FragOff0;
			divert->header.ip.Checksum = ip_header->Checksum;

			//when traffic from client to backdoor server
			if (ntohs(tcp_header->DstPort) == atoi(argv[1]))
			{
				divert->header.tcp.SrcPort = tcp_header->SrcPort;
				divert->header.tcp.DstPort = htons(atoi(argv[2]));
			}

			//when traffic from backdoor server to client
			if (ntohs(tcp_header->SrcPort) == atoi(argv[2]) && tcp_header->DstPort == orig_client_tcpSrcPort)
			{
				divert->header.tcp.SrcPort = htons(atoi(argv[1]));
				divert->header.tcp.DstPort = orig_client_tcpSrcPort;

				divert->header.ip.SrcAddr = orig_server_ip;
				divert->header.ip.DstAddr = orig_client_ip;
			}

			divert->header.tcp.SeqNum = tcp_header->SeqNum;
			divert->header.tcp.AckNum = tcp_header->AckNum;
			divert->header.tcp.Fin = tcp_header->Fin;
			divert->header.tcp.Ack = tcp_header->Ack;
			divert->header.tcp.Rst = tcp_header->Rst;
			divert->header.tcp.Syn = tcp_header->Syn;
			divert->header.tcp.Psh = tcp_header->Psh;
			divert->header.tcp.Urg = tcp_header->Urg;
			divert->header.tcp.Window = tcp_header->Window;
			divert->header.tcp.Checksum = tcp_header->Checksum;
			divert->header.tcp.Reserved1 = tcp_header->Reserved1;
			divert->header.tcp.Reserved2 = tcp_header->Reserved2;

			if (payload != NULL) {
				memcpy(divert->data, payload, payload_len);
			}

			if (!disablechecksum) {
				WinDivertHelperCalcChecksums((PVOID)divert, divert_len,
					0);
			}
		}

		// show content of the modified packets
		if (debug) {
			printf("[DEBUG] Modified packets:\n\t");
			DebugPrint(payload, divert, pack, console, payload_len, i, packet_len, addr, packet);
		}

		// packet without data
		if (payload == NULL) {
			if (!WinDivertSend(handle, (PVOID)pack, packet_len, &addr, NULL))
			{
				fprintf(stderr, "[WARNING]: failed to reinject packet (%d)\n",
					GetLastError());
			}
		}

		//packet with data
		else {
			// Re-inject the modified packet.
			if (!WinDivertSend(handle, (PVOID)divert, divert_len, &addr, NULL))
			{
				fprintf(stderr, "[WARNING]: failed to reinject packet (%d)\n",
					GetLastError());
			}

			free(divert);
		}

		if (debug) {
			putchar('\n');
			SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		}
	}
}


static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);
	packet->TTL = 64;
}

/*
* Initialize a TCPPACKET.
*/
static void PacketIpTcpInit(PTCPPACKET packet)
{
	memset(packet, 0, sizeof(TCPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Length = htons(sizeof(TCPPACKET));
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}


static void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

static void DebugPrint(PVOID payload, PDATAPACKET divert, PTCPPACKET pack, HANDLE console,
	UINT payload_len, UINT i, UINT packet_len, WINDIVERT_ADDRESS addr, unsigned char packet[MAXBUF]) {
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	//UINT packet_len;

	// packet without data
	if (payload == NULL) {
		DebugPrintPacket1((PTCPPACKET)pack, console);
	}

	// packet with data
	else {
		//todo call with divert
		WinDivertHelperParsePacket(divert, packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, &payload, &payload_len);

		DebugPrintPacket2((PTCPPACKET)divert, console, addr,
			ip_header, i, tcp_header, packet_len, packet);
		printf("This is data section only!\n");
		for (i = 0; i < payload_len; i++)
		{
			if (i % 40 == 0)
			{
				printf(":\n\t");
			}
			if (isprint(divert->data[i]))
			{
				putchar(divert->data[i]);
			}
			else
			{
				putchar('.');
			}
		}
		putchar('\n');
		SetConsoleTextAttribute(console,
			FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
}

static void DebugPrintPacket1(PTCPPACKET pack, HANDLE console) {
	UINT8 *src_addr = (UINT8 *)&pack->ip.SrcAddr;
	UINT8 *dst_addr = (UINT8 *)&pack->ip.DstAddr;

	SetConsoleTextAttribute(console,
		FOREGROUND_GREEN | FOREGROUND_RED);
	printf("IPv4 [Version=%u HdrLength=%u TOS=%u Length=%u Id=0x%.4X "
		"TTL=%u Protocol=%u "
		"Checksum=0x%.4X SrcAddr=%u.%u.%u.%u DstAddr=%u.%u.%u.%u]\n",
		pack->ip.Version, pack->ip.HdrLength,
		ntohs(pack->ip.TOS), ntohs(pack->ip.Length),
		ntohs(pack->ip.Id), pack->ip.TTL,
		pack->ip.Protocol, ntohs(pack->ip.Checksum),
		src_addr[0], src_addr[1], src_addr[2], src_addr[3],
		dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);


	SetConsoleTextAttribute(console, FOREGROUND_GREEN);
	printf("TCP [SrcPort=%u DstPort=%u SeqNum=%u AckNum=%u "
		"HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u "
		"Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X "
		"UrgPtr=%u]\n",
		ntohs(pack->tcp.SrcPort), ntohs(pack->tcp.DstPort),
		ntohl(pack->tcp.SeqNum), ntohl(pack->tcp.AckNum),
		pack->tcp.HdrLength, pack->tcp.Reserved1,
		pack->tcp.Reserved2, pack->tcp.Urg, pack->tcp.Ack,
		pack->tcp.Psh, pack->tcp.Rst, pack->tcp.Syn,
		pack->tcp.Fin, ntohs(pack->tcp.Window),
		ntohs(pack->tcp.Checksum), ntohs(pack->tcp.UrgPtr));
	putchar('\n');
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void DebugPrintPacket2(PTCPPACKET pack, HANDLE console, WINDIVERT_ADDRESS addr,
	PWINDIVERT_IPHDR ip_header, UINT i, PWINDIVERT_TCPHDR tcp_header, UINT packet_len, unsigned char packet[MAXBUF]) {
	// Dump packet info: 
	putchar('\n');
	SetConsoleTextAttribute(console, FOREGROUND_RED);
	printf("Packet [Direction=%u IfIdx=%u SubIfIdx=%u]\n",
		addr.Direction, addr.IfIdx, addr.SubIfIdx);

	if (ip_header != NULL)
	{
		UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
		UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
		SetConsoleTextAttribute(console,
			FOREGROUND_GREEN | FOREGROUND_RED);
		printf("IPv4 [Version=%u HdrLength=%u TOS=%u Length=%u Id=0x%.4X "
			"TTL=%u Protocol=%u "
			"Checksum=0x%.4X SrcAddr=%u.%u.%u.%u DstAddr=%u.%u.%u.%u]\n",
			ip_header->Version, ip_header->HdrLength,
			ntohs(ip_header->TOS), ntohs(ip_header->Length),
			ntohs(ip_header->Id), ip_header->TTL,
			ip_header->Protocol, ntohs(ip_header->Checksum),
			src_addr[0], src_addr[1], src_addr[2], src_addr[3],
			dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
	}

	if (tcp_header != NULL)
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		printf("TCP [SrcPort=%u DstPort=%u SeqNum=%u AckNum=%u "
			"HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u "
			"Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X "
			"UrgPtr=%u]\n",
			ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
			ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum),
			tcp_header->HdrLength, tcp_header->Reserved1,
			tcp_header->Reserved2, tcp_header->Urg, tcp_header->Ack,
			tcp_header->Psh, tcp_header->Rst, tcp_header->Syn,
			tcp_header->Fin, ntohs(tcp_header->Window),
			ntohs(tcp_header->Checksum), ntohs(tcp_header->UrgPtr));
	}
	SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);

	for (i = 0; i < packet_len; i++)
	{
		if (i % 30 == 0)
		{
			printf("\n\t");
		}
		printf("%02x", packet[i]);
	}
	putchar('\n');
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}