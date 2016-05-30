#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEFAULT_NETWORK 0x0001a8c0 // 192.168.1.0
#define DEFAULT_MASKBITS 24 // 255.255.255.0
#define DEFAULT_INTERFACE "br-lan"

#define MASKBITS_MIN 16
#define MASKBITS_MAX 30

// The mask must have at least 16 bits which means a maximum of 2^(32-16) = 65536 hosts.
#define NHOSTS 65536

// Define an array which will hold the number of bytes transferred by different hosts.
unsigned long ips[NHOSTS];

in_addr_t network;
in_addr_t mask;

in_addr_t makemask(int bits)
{
	in_addr_t mask = 1;
	return (mask << bits) - 1;
}

int ainnet(in_addr_t addr)
{
	if ((addr & mask) == network) {
		return 1;
	}

	return 0;
}

void
packet_cb(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct iphdr *ip_ptr;
	int host;

	/*
	  Skip past the Ethernet header and extract the IP header by casting with the
	  iphdr struct borrowed from netinet/ip.h.
	*/
	ip_ptr = (struct iphdr*)(packet + ETH_HLEN);

	if (ainnet(ip_ptr->daddr) && !ainnet(ip_ptr->saddr)) {
		// Get the host number.
		host = ip_ptr->daddr & ~mask;

		// The host number is in big-endian so we convert here.
		ips[ntohl(host)] += header->len;
	}

	if (ainnet(ip_ptr->saddr) && !ainnet(ip_ptr->daddr)) {
		host = ip_ptr->saddr & ~mask;
		ips[ntohl(host)] += header->len;
	}
}

int main(int argc, char *argv[])
{
	int i, mth, opt;

	int maskbits = DEFAULT_MASKBITS;
	char *interface = DEFAULT_INTERFACE;

	in_addr_t ip;
	char ipstr[INET_ADDRSTRLEN];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	struct bpf_program fp;
	char filter_exp[] = "ip";

	network = DEFAULT_NETWORK;

	while ((opt = getopt(argc, argv, "i:n:m:")) != -1) {
		switch (opt) {
		case 'n':
			if (!inet_pton(AF_INET, optarg, &network)) {
				fprintf(stderr, "Could not parse network address\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'm':
			maskbits = atoi(optarg);
			break;
		case 'i':
			interface = optarg;
			break;
		default:
			fprintf(stderr, "Uhhh...\n");
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (maskbits < MASKBITS_MIN) {
		fprintf(stderr, "Mask must have at least %d bits\n", MASKBITS_MIN);
		exit(EXIT_FAILURE);
	}

	if (maskbits > MASKBITS_MAX) {
		fprintf(stderr, "Mask must be under %d bits\n", MASKBITS_MAX + 1);
		exit(EXIT_FAILURE);
	}

	// Make a mask from the number of bits and normalise the network address.
	mask = makemask(maskbits);
	network = network & mask;

	// Setup pcap, sanity check the filter expression, compile it and set it.

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", interface);
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

	/*
	  Find the host number which used the most bytes, ignoring the network and broadcast
	  addresses.
	*/
	for (i = 1, mth = 1; i < (NHOSTS-1); i++)
		if (ips[i] > ips[mth])
			mth = i;

	/*
	  Get the full IP address from the host number and network address, and translate it
	  into human-readable form.
	*/
	ip = htonl(mth) | network;
	inet_ntop(AF_INET, &ip, ipstr, INET_ADDRSTRLEN);

	printf("%s\n", ipstr);

	return EXIT_SUCCESS;
}
