#include <arpa/inet.h>
#include <byteswap.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define NETWORK 0x0001a8c0 // 192.168.1.0
#define NETMASK 0x00ffffff // 255.255.255.0

#define NHOSTS 256

unsigned long ips[NHOSTS];

void
packet_cb(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	extern unsigned long ips[];
	const struct iphdr *ip_ptr;
	u_int32_t host;

	ip_ptr = (struct iphdr*)(packet + ETH_HLEN);

	if ((ip_ptr->daddr & NETMASK) == NETWORK) {
		host = ip_ptr->daddr & ~NETMASK;
		ips[ntohl(host)] += header->len;
	}

	if ((ip_ptr->saddr & NETMASK) == NETWORK) {
		host = ip_ptr->saddr & ~NETMASK;
		ips[ntohl(host)] += header->len;
	}
}

int main(int argc, char *argv[])
{
	int i;
	int mth = 1;

	u_int32_t ip;
	char ipstr[INET_ADDRSTRLEN];

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	struct bpf_program fp;
	char filter_exp[] = "ip";

	if (argc < 2) {
		fprintf(stderr, "No argument supplied\n");
		exit(EXIT_FAILURE);
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", dev);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < NHOSTS; i++)
		ips[i] = 0;

	pcap_loop(handle, 512, packet_cb, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);

	// Ignore the network and broadcast addresses
	for (i = 1; i < (NHOSTS-1); i++)
		if (ips[i] > ips[mth])
			mth = i;

	ip = htonl((u_int32_t) mth) | NETWORK;
	inet_ntop(AF_INET, &ip, ipstr, INET_ADDRSTRLEN);

	printf("%s\n", ipstr);

	return EXIT_SUCCESS;
}
