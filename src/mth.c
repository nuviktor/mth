#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define NETWORK 0x0001a8c0 // 192.168.1.0
#define NETMASK 0x00ffffff // 255.255.255.0

/*
  Completely hacky and not tied to the netmask at all (which it should be).
  Will be improved when I decide if a hash table is the best way to implement it,
  and learn how to use it if I do.
*/
#define NHOSTS 256

// Define an array which will hold the number of bytes transferred by different hosts.
unsigned long ips[NHOSTS];

void
packet_cb(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	extern unsigned long ips[];
	const struct iphdr *ip_ptr;
	u_int32_t host;

	/*
	  Skip past the Ethernet header and extract the IP header by casting with the
	  iphdr struct borrowed from netinet/ip.h.
	*/
	ip_ptr = (struct iphdr*)(packet + ETH_HLEN);

	/*
	  Get the destination address, then bitwise AND it with the netmask to check if it's
	  in the network of hosts we want to track.
	*/
	if ((ip_ptr->daddr & NETMASK) == NETWORK) {
		// Get the host number.
		host = ip_ptr->daddr & ~NETMASK;

		// The host number is in big-endian so we convert here.
		ips[ntohl(host)] += header->len;
	}

	// Same with the source address.
	if ((ip_ptr->saddr & NETMASK) == NETWORK) {
		host = ip_ptr->saddr & ~NETMASK;
		ips[ntohl(host)] += header->len;
	}
}

int main(int argc, char *argv[])
{
	int i;
	int mth;

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

	// Setup pcap, sanity check the filter expression, compile it and set it.

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
	ip = htonl(mth) | NETWORK;
	inet_ntop(AF_INET, &ip, ipstr, INET_ADDRSTRLEN);

	printf("%s\n", ipstr);

	return EXIT_SUCCESS;
}
