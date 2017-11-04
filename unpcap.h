#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>
//#include <bits/endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

// Ethernet header format
struct Ethernet
{
	uint8_t dstmac[6];
	uint8_t srcmac[6];
	uint16_t type;	// upper layer protocol
}__attribute__((packed));

// IPv4 header format
struct Ipv4
{ 
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl:4;	// Internet header length
	unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t tos;	// DSCP & ECN
	uint16_t tot_len;	// total packet length
	uint16_t id;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int fragoff1:5;
	unsigned int flags:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int flags:3;
	unsigned int fragoff1:5;
	
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t fragoff2;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t srcip;
	uint32_t dstip;
	/*The options start here. */ 
}__attribute__((packed));

// TCP header format
struct Tcp
{ 
	uint16_t srcport;
	uint16_t dstport;
	uint32_t seq;
	uint32_t ackseq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN 
	uint16_t ns:1;
	uint16_t res:3;
	uint16_t doff:4;

	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t ece:1;
	uint16_t cwr:1;
#  elif __BYTE_ORDER == __BIG_ENDIAN 
	uint16_t doff:4;
	uint16_t res:3;
	uint16_t ns:1;

	uint16_t cwr:1;
	uint16_t ece:1;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#  else 
#   error "Adjust your <bits/endian.h> defines" 
#  endif 
	uint16_t wndsize;
	uint16_t checksum;
	uint16_t urgptr;
}__attribute__((packed));