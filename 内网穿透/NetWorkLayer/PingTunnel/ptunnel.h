/*	ptunnel.h
	ptunnel is licensed under the BSD license:
	
	Copyright (c) 2004-2011, Daniel Stoedle <daniels@cs.uit.no>,
	Yellow Lemon Software. All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	- Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.

	- Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

	- Neither the name of the Yellow Lemon Software nor the names of its
	  contributors may be used to endorse or promote products derived from this
	  software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
		
	Contacting the author:
	You can get in touch with me, Daniel Stødle (that's the Norwegian letter oe,
	in case your text editor didn't realize), here: <daniels@cs.uit.no>
	
	The official ptunnel website is here:
	<http://www.cs.uit.no/~daniels/PingTunnel/>
	
	Note that the source code is best viewed with tabs set to 4 spaces.
*/

#ifndef PING_TUNNEL_H
	#define PING_TUNNEL_H

//	Includes
#ifndef WIN32
  	#include	<sys/unistd.h>
  	#include	<sys/types.h>
  	#include	<sys/socket.h>
  	#include	<netinet/in.h>
  	#include	<arpa/inet.h>
  	#include	<netdb.h>
	#include	<pthread.h>
	#include	<errno.h>
	#include	<net/ethernet.h>
	#include	<syslog.h>
	#include	<pwd.h>
	#include	<grp.h>
#endif /* !WIN32 */
	#include	<stdarg.h>
	#include	<unistd.h>
  	#include	<stdio.h>
  	#include	<stdlib.h>
  	#include	<string.h>
  	#include	<time.h>
  	#include	<sys/time.h>
  	#include	<signal.h>
  	#include	<stdint.h>
  	#include	<pcap.h>

#ifdef WIN32
	#include    <winsock2.h>
	typedef int socklen_t;
	typedef uint32_t in_addr_t;
	#define ETH_ALEN        6               /* Octets in one ethernet addr   */
	struct ether_header
	{
		u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
		u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
		u_int16_t ether_type;                 /* packet type ID field */
	};
#endif /* WIN32 */

//	Constants
#define	false		0
#define	true		1
#define	bool		char

enum {
	kOpt_undefined			= 0,		//	Constants for parsing options
	kOpt_set_proxy_addr,
	kOpt_set_mode,
	kOpt_set_password,
	kOpt_set_tcp_port,
	kOpt_set_tcp_dest_addr,
	kOpt_set_tcp_dest_port,
	kOpt_set_verbosity,
	kOpt_set_max_tunnels,
	kOpt_set_non_privileged,
	kOpt_set_pcap_device,
	kOpt_set_log_file,
	kOpt_set_unpriv_user,
	kOpt_set_unpriv_group,
	kOpt_set_root_dir,
	kOpt_set_selinux_context,
	kOpt_daemonize,
	
	kMode_forward			= 0,	//	Ping tunnel's operating mode (client or
	kMode_proxy,					//	proxy)
	
	kMax_tunnels			= 10,/*	Set this constant to the number of concurrent
									connections you wish to handle by default. */
	
	kNo_log					= -1,	//	Different verbosity levels.
	kLog_error				= 0,
	kLog_info,
	kLog_event,
	kLog_verbose,
	kLog_debug,
	kLog_sendrecv,
	
	kMajor_version			= 0,	//	Major (0.xx) and minor (x.70) version
	kMinor_version			= 72,	//	numbers.
	
	kIP_packet_max_size		= 576,
	kIP_header_size			= 20,	//	In bytes, mind you
	kIP_actual_size			= (kIP_packet_max_size - kIP_header_size) - ((kIP_packet_max_size - kIP_header_size) % 8),
	kICMP_header_size		= 8,	//	Also in bytes
	
	kDefault_buf_size		= 1024,	/*	This constant control the maximum size of
										the payload-portion of the ICMP packets
										we send. Note that this does not include
										the IP or ICMP headers!	*/
	
	kICMP_echo_request		= 8,	//	Type code for echo request and replies
	kICMP_echo_reply		= 0,
	
	kPing_window_size		= 64,	// number of packets we can have in our send/receive ring
	
	/*	Tunnels are automatically closed after one minute of inactivity. Since
		we continously send acknowledgements between the two peers, this mechanism
		won't disconnect "valid" connections.
	*/
	kAutomatic_close_timeout	= 60,	//	Seconds!
	
	kMD5_digest_size		= 16,	//	size of md5 digest in bytes
	
	/*	These constants are used to indicate the protocol state. The protocol
		works as follows:
		- The identifier is used by both the proxy and the forwarder
		to identify the session (and thus the relevant sockets).
		- The seq-no of the ping packet is used in a sliding-window-esque
		way, and to identify the order of data.
		
		The protocol can be in any of the following states:
		kProxy_start		Causes the proxy to open a connection to the given
							host and port, associating the ID with the socket,
							before the data on the socket are transmitted.
		kProxy_data			Indicates that the packet contains data from the proxy.
							Data ordering is indicated by the seq-no, which will start
							at 0. (The proxy and forwarder maintain different seq-nos.)
		kUser_data			This packet contains user data.
		kConnection_close	Indicates that the connection is being closed.
		kProxy_ack and		Acknowledges the packet (and all packets before it) with seq_no = ack.
		kUser_ack			This is used if there are no implicit acknowledgements due to data
							being sent.
		
		Acknowledgements work by the remote peer acknowledging the last
		continuous seq no it has received.
		
		Note: A proxy receiving a kProxy_data packet, or a user receiving a
		kUser_data packet, should ignore it, as it is the host operating system
		actually returning the ping. This is mostly relevant for users, and for
		proxies running in unprivileged mode.
	*/
	kProxy_start			= 0,
	kProto_ack,
	kProto_data,
	kProto_close,
	kProto_authenticate,
	kNum_proto_types,
	
	kUser_flag				= 1 << 30,	//	set when packet comes from a user
	kProxy_flag				= 1 << 31,	//	set when packet comes from the proxy
	kFlag_mask				= kUser_flag | kProxy_flag,
	
	kDNS_port				= 53,
};

#define	kPing_tunnel_magic		0xD5200880
//	Resend packets after this interval (in seconds)
#define	kResend_interval		1.5

/*	ping_tunnel_pkt_t: This data structure represents the header of a ptunnel
	packet, consisting of a magic number, the tunnel's destination IP and port,
	as well as some other fields. Note that the dest IP and port is only valid
	in packets from the client to the proxy.
*/
typedef struct {
	uint32_t	magic,		//	magic number, used to identify ptunnel packets.
				dst_ip,		//	destination IP and port (used by proxy to figure
				dst_port,	//	out where to tunnel to)
				state,		//	current connection state; see constants above.
				ack,		//	sequence number of last packet received from other end
				data_len;	//	length of data buffer
	uint16_t	seq_no,		//	sequence number of this packet
				id_no;		//	id number, used to separate different tunnels from each other
	char		data[0];	//	optional data buffer
} __attribute__ ((packed)) ping_tunnel_pkt_t;


/*	ip_packet_t: This is basically my own definition of the IP packet, which
	of course complies with the official definition ;) See any good book on IP
	(or even the RFC) for info on the contents of this packet.
*/
typedef struct {
	uint8_t			vers_ihl,
					tos;
	uint16_t		pkt_len,
					id,
					flags_frag_offset;
	uint8_t			ttl,
					proto;	// 1 for ICMP
	uint16_t		checksum;
	uint32_t		src_ip,
					dst_ip;
	char			data[0];
} __attribute__ ((packed)) ip_packet_t;


/*	icmp_echo_packet_t: This is the definition of a standard ICMP header. The
	ptunnel packets are constructed as follows:
	[    ip header (20 bytes)   ]
	[   icmp header (8 bytes)   ]
	[ ptunnel header (28 bytes) ]
	
	We actually only create the ICMP and ptunnel headers, the IP header is
	taken care of by the OS.
*/
typedef struct {
	uint8_t			type,
					code;
	uint16_t		checksum,
					identifier,
					seq;
	char			data[0];
} __attribute__ ((packed)) icmp_echo_packet_t;


/*	pt_thread_info_t: A simple (very simple, in fact) structure that allows us
	to pass an arbitrary number of params to the threads we create. Currently,
	that's just one single parameter: The socket which the thread should listen
	to.
*/
typedef struct {
	int			sock;
} pt_thread_info_t;


/*	forward_desc_t: Describes a piece of that needs to be forwarded. This
	structure is used for receiving data from the network, and for subsequent
	forwarding over TCP:
	
	1. Client sends data to proxy over ICMP
	2. Proxy receives the data, and puts it into a forward_desc_t
	3. The proxy starts send()-ing the data over the TCP socket to the destination,
	   decreasing forward_desc_t->remaining with the number of bytes transferred.
	4. Once remaining reaches 0, the forward_desc_t is removed from the receive
	   ring.
	
	The same procedure is followed in proxy-to-client communication. Just replace
	proxy with client and vice versa in the list above.
*/
typedef struct {
	int			seq_no,		//	ping_tunnel_pkt_t seq_no
				length,		//	length of data
				remaining;	//	amount of data not yet transferred
	char		data[0];
} forward_desc_t;


/*	icmp_desc_t: This structure is used to track the ICMP packets sent by either
	the client or proxy. The last_resend variable is used to prevent resending
	the packet too often. Once the packet is acknowledged by the remote end,
	it will be removed from the send-ring, freeing up space for more outgoing
	ICMP packets.
*/
typedef struct {
	int					pkt_len;		// total length of ICMP packet, including ICMP header and ptunnel data.
	double				last_resend;
	int					resend_count;
	uint16_t			seq_no,
						icmp_id;
	icmp_echo_packet_t	*pkt;
} icmp_desc_t;


/*	challenge_t: This structure contains the pseudo-random challenge used for
	authentication.
*/
typedef struct challenge_t {
	uint32_t			sec,		//	tv_sec as returned by gettimeofday
						usec_rnd,	//	tv_usec as returned by gettimeofday + random value
						random[6];	//	random values
} __attribute__ ((packed)) challenge_t;


/*	xfer_stats_t: Various transfer statistics, such as bytes sent and received,
	number of ping packets sent/received, etc.
*/
typedef struct xfer_stats_t {
	double				bytes_in,
						bytes_out;
	uint32_t			icmp_in,
						icmp_out,
						icmp_resent,
						icmp_ack_out;
} xfer_stats_t;


/*	proxy_desc_t: This massive structure describes a tunnel instance.
*/
typedef struct proxy_desc_t {
	int					sock,			//	ICMP or UDP socket
						bytes,			//	number of bytes in receive buffer
						should_remove;	//	set to true once this instance should be removed
	char				*buf;			//	data buffer, used to receive ping and pong packets
	uint16_t			id_no,
						my_seq,
						ping_seq,
						next_remote_seq,
						pkt_type,
						remote_ack_val,
						icmp_id;
	int					recv_idx,		//	first available slot in recv ring
						recv_xfer_idx,	//	current slot in recv ring being transferred
						send_idx,		//	first available slot in send ring
						send_first_ack,	//	first packet in send ring not yet acked
						recv_wait_send,	//	number of items in recv ring awaiting send
						send_wait_ack,	//	number of items in send ring awaiting ack
						next_resend_start,
						authenticated;
	challenge_t			*challenge;		//	Contains the challenge, if used.
	uint32_t			state,			//	Protocol state
						type_flag,		//	Either kProxy_flag or kUser_flag
						dst_ip,			//	IP and port to which data should be forwarded.
						dst_port;
	struct sockaddr_in	dest_addr;		//	Same as above
	double				last_ack,		//	Time when last ack packet was sent.
						last_activity;	//	Time when a packet was last received.
	icmp_desc_t			send_ring[kPing_window_size];
	forward_desc_t		*recv_ring[kPing_window_size];
	xfer_stats_t		xfer;
	struct proxy_desc_t	*next;
} proxy_desc_t;


/*	pqueue_elem_t: An queue element in the pqueue structure (below).
*/
typedef struct pqueue_elem_t {
	int						bytes;		// size of data buffer
	struct pqueue_elem_t	*next;		// next queue element (if any)
	char					data[0];	// data (duh!)
} pqueue_elem_t;


/*	pqueue_t: A simple queue strucutre.
*/
typedef struct {
	pqueue_elem_t	*head,
					*tail;
	int				elems;
} pqueue_t;

/*	pcap_info_t: Structure to hold information related to packet capturing.
*/
typedef struct {
	pcap_t				*pcap_desc;
	struct bpf_program	fp;		//	Compiled filter program
	uint32_t			netp,
						netmask;
	char				*pcap_err_buf,	//	Buffers for error and packet info
						*pcap_data_buf;
	pqueue_t			pkt_q;			//	Queue of packets to process
} pcap_info_t;


//	Prototypes (sorry about the long lines..)
	void		usage(char *exec_name);
	void*		pt_proxy(void *args);
	void		pcap_packet_handler(u_char *refcon, const struct pcap_pkthdr *hdr, const u_char* pkt);
	void		handle_packet(char *buf, int bytes, int is_pcap, struct sockaddr_in *addr, int icmp_sock);
	
	proxy_desc_t*	create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id, int sock, struct sockaddr_in *addr, uint32_t dst_ip, uint32_t dst_port, uint32_t init_state, uint32_t type);
	void		remove_proxy_desc(proxy_desc_t *cur, proxy_desc_t *prev);
	
	void		pt_forwarder(void);
	
	void		print_statistics(xfer_stats_t *xfer, int is_continuous);
	int			queue_packet(int icmp_sock, uint8_t type, char *buf, int num_bytes, uint16_t id_no, uint16_t icmp_id, uint16_t *seq, icmp_desc_t ring[], int *insert_idx, int *await_send, uint32_t ip, uint32_t port, uint32_t state, struct sockaddr_in *dest_addr, uint16_t next_expected_seq, int *first_ack, uint16_t *ping_seq);
	uint32_t	send_packets(forward_desc_t *ring[], int *xfer_idx, int *await_send, int *sock);
	void		handle_data(icmp_echo_packet_t *pkt, int total_len, forward_desc_t *ring[], int *await_send, int *insert_idx, uint16_t *next_expected_seq);
	void		handle_ack(uint16_t seq_no, icmp_desc_t ring[], int *packets_awaiting_ack, int one_ack_only, int insert_idx, int *first_ack, uint16_t *remote_ack, int is_pcap);
	forward_desc_t*	create_fwd_desc(uint16_t seq_no, uint32_t data_len, char *data);
	void		init_ip_packet(ip_packet_t *packet, uint16_t id, uint16_t frag_offset, uint16_t pkt_len, uint8_t ttl, uint32_t src_ip, uint32_t dst_ip, bool is_last_frag, bool dont_frag);
	uint16_t	calc_ip_checksum(ip_packet_t *pkt);
	uint16_t	calc_icmp_checksum(uint16_t *data, int bytes);
	
	challenge_t*	generate_challenge(void);
	void			generate_response(challenge_t *challenge);
	int				validate_challenge(challenge_t *local, challenge_t *remote);
	
	void		send_termination_msg(proxy_desc_t *cur, int icmp_sock);
	
	char*	f_inet_ntoa(uint32_t ip);
	void	pt_log(int level, char *fmt, ...);
	double	time_as_double(void);
#endif
