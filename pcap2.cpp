#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnet.h>

#define MAX_DATA_LEN 10

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
        return false;
    }

    param->dev_ = argv[1];
    return true;
}

void print_mac_addr(const char* title, const uint8_t* mac_addr) {
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n", title,
           mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

void print_ip_addr(const char* title, const uint32_t ip_addr) {
    printf("%s %s\n", title, inet_ntoa(*(struct in_addr*)&ip_addr));
}

void print_port(const char* title, const uint16_t port) {
    printf("%s %u\n", title, ntohs(port));
}

void print_data(const char* title, const uint8_t* data, const int data_len) {
    printf("%s ", title);
    for (int i = 0; i < data_len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void handle_packet(u_char* arg, const struct pcap_pkthdr* header, const u_char* packet) {
    struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)packet;
    if (ntohs(ethernet_hdr->ether_type) != ETHERTYPE_IP) {
        return;  // not an IP packet
    }

    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return;  // not a TCP packet
    }

    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
    int tcp_hdr_len = tcp_hdr->th_off * 4;

    printf("%u bytes captured\n", header->caplen);
    print_mac_addr("src mac", ethernet_hdr->ether_shost);
    print_mac_addr("dst mac", ethernet_hdr->ether_dhost);
    print_ip_addr("src ip", ip_hdr->ip_src.s_addr);
    print_ip_addr("dst ip", ip_hdr->ip_dst.s_addr);
    print_port("src port", tcp_hdr->th_sport);
    print_port("dst port", tcp_hdr->th_dport);

    if (tcp_hdr_len > sizeof(struct libnet_tcp_hdr)) {
        const uint8_t* data = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + tcp_hdr_len;
        int data_len = header->caplen - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr) - tcp_hdr_len;
        
        if (data_len > 0) {
            print_data("data", data, data_len > MAX_DATA_LEN ? MAX_DATA_LEN : data_len);
            }
        }
    }

int main(int argc, char* argv[]) {
    
    if (!parse(&param, argc, argv)) {
    return -1;
    }

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
        if (res == -1 || res == -2) break;

        handle_packet(NULL, header, packet);
    }

    pcap_close(pcap);
    
    return 0;
}



