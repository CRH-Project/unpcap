#include "unpcap.h"

#define USRNUM 5000
#define APNUM 500
#define ISUSR(ip) (((ip) & 0xffff0000) == 0xc0a80000)
#define ISHTTP(port) ((port) == 80)
#define ISSSL(port) ((port) == 443)
#define ISWELLKNOWN(port) ((port) <= 1023)
// Only consider "Advantec"
#define ISAP(mac) (mac[0] == 0x0 && mac[1] == 0xb && mac[2] == 0xab)

struct User{
	int ip;
	int upload;
	int text, image, audio, video, msg;
	int zip, octstr, otherapp;
} usr[USRNUM];

struct Ap {
	uint8_t mac[6];
	long long upload;
	long long download;
} ap[APNUM];

struct User *find_user(int ip) {
	for(int i = 0; i < USRNUM; i++) {
		if(usr[i].ip == ip) return &usr[i];
	}
	return NULL;
}

struct Ap *find_ap(const uint8_t *mac) {
	int flag;
	for(int i = 0; i < APNUM; i++) {
		flag = 1;
		for(int j = 0; j < 6; j++) {
			if(mac[j] != ap[i].mac[j]) {
				flag = 0;
				break;
			}
		}
		if(flag) return &ap[i];
	}
	return NULL;
}

// Find a specific field(sign) in the header(src), and copy it to dst
int get_field(char *dst, const char *src, char *sign) {
	if(!dst || !src || !sign) return -1;

	int i = 0;
	char tmp, *start = strstr(src, sign);
	if(!start) return -1;

	start += strlen(sign); // "Content-Type: XXX"

	while(1) {
		tmp = *start;
		if(tmp == '\r' || tmp == ';' || tmp == ',' || tmp == '\0')
			break;
		dst[i++] = tmp;
		start++;
	}
	dst[i] = '\0';
	return 0;
}

int total = 0, curusr = 0, curap = 0;
struct in_addr in;

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
	total++;

	// Only consider a protocol stack of Ethernet, IPv4, TCP and HTTP
	// We can get a pointer pointing to each header
	const struct Ethernet *link = (struct Ethernet *)pkt;
	const struct Ipv4 *net = (struct Ipv4 *)(pkt + sizeof(struct Ethernet));
	const struct Tcp *trans = (struct Tcp *)((u_char *)net + 4 * net->ihl);
	const char *app = (char *)((u_char *)trans + 4 * trans->doff);

	// Add AP to the ap list, if it is not full
	if(curap < APNUM && ISAP(link->srcmac) && !find_ap(link->srcmac))
		memcpy(ap[curap++].mac, link->srcmac, 6);
	if(curap < APNUM && ISAP(link->dstmac) && !find_ap(link->dstmac))
		memcpy(ap[curap++].mac, link->dstmac, 6);

	// Count bytes for this AP
	struct Ap *srcap = find_ap(link->srcmac), *dstap = find_ap(link->dstmac);
	if(srcap) srcap->download += h->len;
	if(dstap) dstap->upload += h->len;

	// IP address in integer
	const int srcip = ntohl(net->srcip), srcport = ntohs(trans->srcport);
	const int dstip = ntohl(net->dstip), dstport = ntohs(trans->dstport);

	// IP address in string
	char srcip_str[20], dstip_str[20];
	in.s_addr = net->srcip;
	strcpy(srcip_str, inet_ntoa(in));
	in.s_addr = net->dstip;
	strcpy(dstip_str, inet_ntoa(in));

	/*
		Filter out frames shorter than 100 bytes (most of which are TCP control packets),
		or not using IPv4, or not using TCP, or not sent to or received by users.
	*/ 
	if(h->len < 100) return;

	if(net->version != 0x4) return;
	if(net->protocol != 0x6) return;
	if(!ISUSR(srcip) && !ISUSR(dstip)) return;

	// Get specific field from app-layer headers
	char len[100], type[100];
	int r, _len;
	if((r = get_field(len, app, "Content-Length: ")) < 0) return;
	if((r = get_field(type, app, "Content-Type: ")) < 0) return;

	_len = atoi(len);

	// Add user to the user list, if it is not full
	if(curusr < USRNUM && ISUSR(srcip) && !find_user(srcip))
		usr[curusr++].ip = srcip;
	if(curusr < USRNUM && ISUSR(dstip) && !find_user(dstip))
		usr[curusr++].ip = dstip;

	// Only consider frames sent to or received by users in the user list
	struct User *src = find_user(srcip), *dst = find_user(dstip);
	if(curusr == USRNUM && !src && !dst) return;

	// User POSTs something to server
	if(src && ISHTTP(dstport)) {
		src->upload += _len;
		//printf("Frame %d %s:%d upload to %s:%d, %s, %s\n",
		//		total, srcip_str, srcport, dstip_str, dstport, type, len);
	}

	// User GETs something from server
	// Or, server responds to user's POST (Content-Length = 0)
	if(dst && ISHTTP(srcport) && _len > 0) {
		if(strstr(type, "text")) dst->text += _len;
		else if(strstr(type, "image"))
			dst->image += _len;
		else if(strstr(type, "audio"))
			dst->audio += _len;
		else if(strstr(type, "video"))
			dst->video += _len;
		else if(strstr(type, "message"))
			dst->msg += _len;
		else if(strstr(type, "application")) {
			if(strstr(type, "octet-stream"))
				dst->octstr += _len;
			else if(strstr(type, "zip"))
				dst->zip += _len;
			else dst->otherapp += _len;
		}
		//printf("Frame %d %s:%d download from %s:%d, %s, %s\n",
		//		total, dstip_str, dstport, srcip_str, srcport, type, len);
	}
	return;
}

int main(int argc, char *argv[]) {
	u_char err[100];
	int i, j;

	if(argc != 2) {
		printf("usage: unpcap FILENAME\n");
		exit(0);
	}

	FILE *fp = fopen(argv[1], "r");
	if(!fp) {
		printf("File does not exist\n");
	}

	pcap_t *pcap = pcap_fopen_offline(fp, NULL);
	pcap_loop(pcap, 0, handler, err);

	//printf("%-20s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %s\n",
	printf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			"User IP", "Upload", "Text", "Image", "Octet-stream", "Zip", "Other App", "Audio", "Video");

	for(i = 0; i < curusr; i++) {
		in.s_addr = htonl(usr[i].ip);
		//printf("%-25s %-15d %-15d %-15d %-15d %-15d %-15d %-15d %d\n",
		printf("%s,%d,%d,%d,%d,%d,%d,%d,%d\n",
				inet_ntoa(in), usr[i].upload, usr[i].text, usr[i].image, usr[i].octstr, usr[i].zip, usr[i].otherapp,
				usr[i].audio, usr[i].video);
	}


	//printf("%-20s %-15s %s\n",
	printf("%s,%s,%s\n",
			 "AP MAC", "Upload", "Download");
	for(i = 0; i < curap; i++) {
		for(j = 0; j < 6; j++) {
			printf("%02x", ap[i].mac[j]);
			if(j != 5) printf(":");
		}
		//printf("    ");
		printf(",");
		//printf("%-15lld %lld\n",
		printf("%lld,%lld\n",
				ap[i].upload, ap[i].download);
	}
	//printf("%s\n", err);
	return 0;
}