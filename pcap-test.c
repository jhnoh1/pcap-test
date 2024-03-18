#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};


struct ether_h{
	u_int8_t to[6];
	u_int8_t from[6];
	u_int16_t type;
};

struct ipv4_h{
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[4], ip_dst[4]; /* source and dest address */
};


struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
        u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};



bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		struct ether_h *ehead = packet;
		if(ntohs(ehead->type)!= 0x0800) continue;
		struct ipv4_h *iphead = packet+sizeof(struct ether_h);
		if(ntohs(iphead->ip_p)!= 6) continue;
		struct libnet_tcp_hdr *tcphead = packet + sizeof(struct ether_h)  + iphead-> ip_len;
		u_int8_t *src_mac = ehaed -> from;
		u_int8_t *dst_mac = ehead -> to;
		u_int8_t *src_ip = iphead -> ip_src;
		u_int8_t *dst_ip = iphead -> ip_dst;
		u_int16_t src_tcp = tcpheader -> th_sport;
		u_int16_t dst_tcp = tcpheader -> th_dport;
		u_int8_t tcp_len = (tcpheader -> th_off)*4;
		u_int8_t *packetdata = packet + sizeof(struct ether_h)  + iphead-> ip_hl;
		printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
		printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
		printf("src ip : %d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
                printf("dst ip : %d.%d.%d.%d\n",dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3]);
		printf("src tcp : %d\n",ntohs(src_tcp));
                printf("dst tcp : %d\n",ntohs(dst_tcp));
		if(tcplen==20)continue;
		if(tcplen>=30){
			printf("Data : ");
			for(int i=0; i<10;i++){
				printf("%02x",packetdata[i]);
			}
		}
		else{
			print("Data : ");
			for(int i=0; i<tcplen-20;i++){
                                printf("%02x",packetdata[i]);
                        }

		}


	}

	pcap_close(pcap);
}
