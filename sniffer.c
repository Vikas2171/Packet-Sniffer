#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

// Define ETHER_HDR_LEN if not already defined by your system headers.
#ifndef ETHER_HDR_LEN
#define ETHER_HDR_LEN 14
#endif

// Ethernet Header Structure
struct eth_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
} __attribute__((packed));

// IP Header Structure (IPv4)
struct ip_header {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int   ip_hl:4,    // 4 bits for header length
            ip_v:4;     // 4 bits for version
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
    u_int   ip_v:4,
            ip_hl:4;
    #endif
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct  in_addr ip_src, ip_dst;
} __attribute__((packed));

#define IP_HL(ip)               (((ip)->ip_hl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_v) & 0x0f)

// TCP Header Structure
struct tcp_header {
    u_short th_sport;
    u_short th_dport;
    u_int   th_seq;
    u_int   th_ack;
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int   th_x2:4,
            th_off:4;
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
    u_int   th_off:4,
            th_x2:4;
    #endif
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} __attribute__((packed));

// UDP Header Structure
struct udp_header {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
} __attribute__((packed));

// ARP Header Structure
struct arp_header {
    u_short ar_hrd;     /* Format of hardware address */ // 0x0001 for Ethernet
    u_short ar_pro;     /* Format of protocol address */ // 0x0800 for IPv4
    u_char  ar_hln;     /* Length of hardware address */ // 6 for Ethernet
    u_char  ar_pln;     /* Length of protocol address */ // 4 for IPv4
    u_short ar_op;      /* ARP opcode (request/reply) */ // 1 for request, 2 for reply
    u_char  ar_sha[6];  /* Sender hardware address */
    u_char  ar_spa[4];  /* Sender protocol address (IP) */
    u_char  ar_tha[6];  /* Target hardware address */
    u_char  ar_tpa[4];  /* Target protocol address (IP) */
} __attribute__((packed));

// ICMP Header Structure
struct icmp_header {
    u_char  icmp_type;
    u_char  icmp_code;
    u_short icmp_chksum;
    union { // Union to handle variable 'Contents' part of ICMP
        struct {
            u_short id;
            u_short seq;
        } echo;
        u_int   gateway;    // Gateway address (for Redirect)
        struct {
            u_short unused;
            u_short next_mtu;
        } frag;
        u_char  data[4];
    } un;
} __attribute__((packed));

// Struct to pass multiple arguments to packet_handler
typedef struct {
    pcap_dumper_t *pcap_dumper;
    FILE *text_output_file;
} sniffer_args_t;

// --- Global Statistics Counters ---
static int total_packets_captured = 0;
static int ethernet_broadcast_packets = 0;
static int ip_packets = 0;
static int tcp_packets = 0;
static int udp_packets = 0;
static int icmp_packets = 0;
static int arp_packets = 0;
static int other_ether_packets = 0;
static int other_ip_protocols = 0;

// --- Global Packet Number Counter ---
static int current_packet_number = 0;

// --- Function Prototypes ---
void print_mac(FILE *f, const char *label, const u_char *mac);
void parse_tcp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len);
void parse_udp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len);
void parse_icmp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int packet_len);
void parse_ip_packet(FILE *f, const u_char *packet, int eth_hdr_len, int packet_len);
void parse_arp_packet(FILE *f, const u_char *packet, int eth_hdr_len, int packet_len);

void print_mac(FILE *f, const char *label, const u_char *mac) {
    fprintf(f, "%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
            label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


void parse_tcp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len) {
    tcp_packets++;
    // TCP header starts after IP header
    int tcp_offset = ip_offset + ip_hdr_len;

    if (packet_len < tcp_offset + sizeof(struct tcp_header)) {
        fprintf(f, "  [!] Packet too short for TCP header.\n");
        return;
    }
    struct tcp_header *tcp = (struct tcp_header *)(packet + tcp_offset);

    u_int tcp_header_len = (tcp->th_off * 4);

    if (tcp_header_len < 20 || (tcp_offset + tcp_header_len) > packet_len) {
        fprintf(f, "  [!] Invalid TCP header length: %d bytes\n", tcp_header_len);
        return;
    }

    fprintf(f, "\t\tTCP Header:\n");
    fprintf(f, "\t\t\tSource Port: %d\n", ntohs(tcp->th_sport));
    fprintf(f, "\t\t\tDestination Port: %d\n", ntohs(tcp->th_dport));
    fprintf(f, "\t\t\tSequence Number: %u\n", ntohl(tcp->th_seq));
    fprintf(f, "\t\t\tAcknowledgement Number: %u\n", ntohl(tcp->th_ack));
    fprintf(f, "\t\t\tData Offset (Header Length): %d bytes\n", tcp_header_len);
    fprintf(f, "\t\t\tFlags: 0x%x [ ", tcp->th_flags);
    if (tcp->th_flags & TH_SYN) fprintf(f, "SYN ");
    if (tcp->th_flags & TH_ACK) fprintf(f, "ACK ");
    if (tcp->th_flags & TH_FIN) fprintf(f, "FIN ");
    if (tcp->th_flags & TH_RST) fprintf(f, "RST ");
    if (tcp->th_flags & TH_PUSH) fprintf(f, "PSH ");
    if (tcp->th_flags & TH_URG) fprintf(f, "URG ");
    if (tcp->th_flags & TH_ECE) fprintf(f, "ECE ");
    if (tcp->th_flags & TH_CWR) fprintf(f, "CWR ");
    fprintf(f, "]\n");

    const u_char *payload = packet + tcp_offset + tcp_header_len;
    int payload_len = total_ip_len - (ip_hdr_len + tcp_header_len);

    if (payload_len > 0 && (payload + payload_len) <= (packet + packet_len)) {
        fprintf(f, "\t\t\tTCP Payload Length: %d bytes\n", payload_len);
    } else if (payload_len < 0) {
         fprintf(f, "\t\t\t[!] Malformed TCP packet: Negative payload length.\n");
    } else {
         fprintf(f, "\t\t\tTCP Payload Length: 0 bytes (No payload)\n");
    }
}

void parse_udp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len) {
    udp_packets++;
    // UDP header starts after IP header
    int udp_offset = ip_offset + ip_hdr_len;

    if (packet_len < udp_offset + sizeof(struct udp_header)) {
        fprintf(f, "  [!] Packet too short for UDP header.\n");
        return;
    }
    struct udp_header *udp = (struct udp_header *)(packet + udp_offset);

    fprintf(f, "\t\tUDP Header:\n");
    fprintf(f, "\t\t\tSource Port: %d\n", ntohs(udp->uh_sport));
    fprintf(f, "\t\t\tDestination Port: %d\n", ntohs(udp->uh_dport));
    fprintf(f, "\t\t\tLength: %d bytes (header + data)\n", ntohs(udp->uh_len));

    int udp_payload_len = ntohs(udp->uh_len) - sizeof(struct udp_header);
    const u_char *payload = packet + udp_offset + sizeof(struct udp_header);

    if (udp_payload_len > 0 && (payload + udp_payload_len) <= (packet + packet_len)) {
        fprintf(f, "\t\t\tUDP Payload Length: %d bytes\n", udp_payload_len);
    } else if (udp_payload_len < 0) {
         fprintf(f, "\t\t\t[!] Malformed UDP packet: Negative payload length.\n");
    } else {
         fprintf(f, "\t\t\tUDP Payload Length: 0 bytes (No payload)\n");
    }
}

void parse_icmp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int packet_len) {
    icmp_packets++;
    // ICMP header starts after IP header
    int icmp_offset = ip_offset + ip_hdr_len;

    if (packet_len < icmp_offset + sizeof(struct icmp_header)) {
        fprintf(f, "  [!] Packet too short for ICMP header.\n");
        return;
    }

    struct icmp_header *icmp = (struct icmp_header *)(packet + icmp_offset);

    fprintf(f, "\t\tICMP Header:\n");
    fprintf(f, "\t\t\tType: %d ", icmp->icmp_type);
    fprintf(f, "Code: %d\n", icmp->icmp_code);
    fprintf(f, "\t\t\tChecksum: 0x%04x\n", ntohs(icmp->icmp_chksum));

    switch (icmp->icmp_type) {
        case 0: // Echo Reply
            fprintf(f, "\t\t\tType Detail: Echo Reply\n");
            fprintf(f, "\t\t\tIdentifier: %d\n", ntohs(icmp->un.echo.id));
            fprintf(f, "\t\t\tSequence Number: %d\n", ntohs(icmp->un.echo.seq));
            break;
        case 3: // Destination Unreachable
            fprintf(f, "\t\t\tType Detail: Destination Unreachable\n");
            fprintf(f, "\t\t\tCode Detail: ");
            switch (icmp->icmp_code) {
                case 0: fprintf(f, "Network Unreachable\n"); break;
                case 1: fprintf(f, "Host Unreachable\n"); break;
                case 2: fprintf(f, "Protocol Unreachable\n"); break;
                case 3: fprintf(f, "Port Unreachable\n"); break;
                case 4: fprintf(f, "Fragmentation Needed and DF set\n"); break;
                case 5: fprintf(f, "Source Route Failed\n"); break;
                case 6: fprintf(f, "Destination Network Unknown\n"); break;
                case 7: fprintf(f, "Destination Host Unknown\n"); break;
                case 8: fprintf(f, "Source Host Isolated\n"); break;
                case 9: fprintf(f, "Network Administratively Prohibited\n"); break;
                case 10: fprintf(f, "Host Administratively Prohibited\n"); break;
                case 11: fprintf(f, "Network Unreachable for TOS\n"); break;
                case 12: fprintf(f, "Host Unreachable for TOS\n"); break;
                case 13: fprintf(f, "Communication Administratively Prohibited\n"); break;
                case 14: fprintf(f, "Host Precedence Violation\n"); break;
                case 15: fprintf(f, "Precedence Cutoff in Effect\n"); break;
                default: fprintf(f, "Unknown Code for Destination Unreachable\n"); break;
            }
            break;
        case 8: // Echo Request
            fprintf(f, "\t\t\tType Detail: Echo Request\n");
            fprintf(f, "\t\t\tIdentifier: %d\n", ntohs(icmp->un.echo.id));
            fprintf(f, "\t\t\tSequence Number: %d\n", ntohs(icmp->un.echo.seq));
            break;
        case 11: // Time Exceeded
            fprintf(f, "\t\t\tType Detail: Time Exceeded\n");
            fprintf(f, "\t\t\tCode Detail: ");
            switch (icmp->icmp_code) {
                case 0: fprintf(f, "TTL equals 0 during transit\n"); break;
                case 1: fprintf(f, "TTL equals 0 during reassembly\n"); break;
                default: fprintf(f, "Unknown Code for Time Exceeded\n"); break;
            }
            break;
        case 5: // Redirect
            fprintf(f, "\t\t\tType Detail: Redirect\n");
            fprintf(f, "\t\t\tCode Detail: ");
             switch (icmp->icmp_code) {
                case 0: fprintf(f, "Redirect Datagram for the Network (or default gateway)\n"); break;
                case 1: fprintf(f, "Redirect Datagram for the Host\n"); break;
                case 2: fprintf(f, "Redirect Datagram for the TOS and network\n"); break;
                case 3: fprintf(f, "Redirect Datagram for the TOS and host\n"); break;
                default: fprintf(f, "Unknown Code for Redirect\n"); break;
            }
            fprintf(f, "\t\t\tGateway Address: %s\n", inet_ntoa(*(struct in_addr *)&icmp->un.gateway));
            break;
        default:
            fprintf(f, "\t\t\tType Detail: Unknown ICMP Type or Code Combination\n");
            break;
    }
}

void parse_ip_packet(FILE *f, const u_char *packet, int eth_hdr_len, int packet_len) {
    ip_packets++;
    int ip_offset = eth_hdr_len;

    if (packet_len < ip_offset + sizeof(struct ip_header)) {
        fprintf(f, "  [!] Packet too short for IP header.\n");
        return;
    }
    struct ip_header *ip = (struct ip_header *)(packet + ip_offset);

    u_int ip_header_len = IP_HL(ip) * 4;
    u_int total_ip_len = ntohs(ip->ip_len);

    if (ip_header_len < 20 || (ip_offset + ip_header_len) > packet_len) {
        fprintf(f, "  [!] Invalid IP header length: %d bytes\n", ip_header_len);
        return;
    }

    fprintf(f, "\n\tIP Header:\n");
    fprintf(f, "\t\tVersion: %d\n", IP_V(ip));
    fprintf(f, "\t\tHeader Length: %d bytes\n", ip_header_len);
    fprintf(f, "\t\tTotal Length: %d bytes (including header and data)\n", total_ip_len);
    fprintf(f, "\t\tSource IP: %s\n", inet_ntoa(ip->ip_src));
    fprintf(f, "\t\tDestination IP: %s\n", inet_ntoa(ip->ip_dst));
    fprintf(f, "\t\tProtocol: %d ", ip->ip_p);

    if (ip->ip_p == IPPROTO_TCP) {
        fprintf(f, "(TCP)\n");
        parse_tcp_packet(f, packet, ip_offset, ip_header_len, total_ip_len, packet_len);
    } else if (ip->ip_p == IPPROTO_UDP) {
        fprintf(f, "(UDP)\n");
        parse_udp_packet(f, packet, ip_offset, ip_header_len, total_ip_len, packet_len);
    } else if (ip->ip_p == IPPROTO_ICMP) {
        fprintf(f, "(ICMP)\n");
        parse_icmp_packet(f, packet, ip_offset, ip_header_len, packet_len);
    } else {
        other_ip_protocols++;
        fprintf(f, "(Other IP Protocol: %d)\n", ip->ip_p);
    }
}

void parse_arp_packet(FILE *f, const u_char *packet, int eth_hdr_len, int packet_len) {
    arp_packets++;
    int arp_offset = eth_hdr_len;

    if (packet_len < arp_offset + sizeof(struct arp_header)) {
        fprintf(f, "  [!] Packet too short for ARP header.\n");
        return;
    }
    struct arp_header *arp = (struct arp_header *)(packet + arp_offset);

    fprintf(f, "\tARP Header:\n");
    fprintf(f, "\t\tHardware Type: 0x%04x (%s)\n", ntohs(arp->ar_hrd),
           (ntohs(arp->ar_hrd) == 1) ? "Ethernet" : "Unknown");
    fprintf(f, "\t\tProtocol Type: 0x%04x (%s)\n", ntohs(arp->ar_pro),
           (ntohs(arp->ar_pro) == ETHERTYPE_IP) ? "IPv4" : "Unknown");
    fprintf(f, "\t\tHardware Length: %d\n", arp->ar_hln);
    fprintf(f, "\t\tProtocol Length: %d\n", arp->ar_pln);
    fprintf(f, "\t\tOperation: %d (%s)\n", ntohs(arp->ar_op),
           (ntohs(arp->ar_op) == 1) ? "Request" : (ntohs(arp->ar_op) == 2) ? "Reply" : "Unknown");

    print_mac(f, "\t\tSender MAC", arp->ar_sha);
    fprintf(f, "\t\tSender IP: %d.%d.%d.%d\n",
           arp->ar_spa[0], arp->ar_spa[1], arp->ar_spa[2], arp->ar_spa[3]);

    print_mac(f, "\t\tTarget MAC", arp->ar_tha);
    fprintf(f, "\t\tTarget IP: %d.%d.%d.%d\n",
           arp->ar_tpa[0], arp->ar_tpa[1], arp->ar_tpa[2], arp->ar_tpa[3]);
}


void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    total_packets_captured++;
    current_packet_number++;

    sniffer_args_t *args = (sniffer_args_t *)user_data;
    FILE *output_file = args->text_output_file;

    // Dump the raw packet to the .pcap file
    pcap_dump((u_char *)args->pcap_dumper, header, packet);

    // --- Start of parsed output for the current packet ---
    fprintf(output_file, "\n--- Packet Captured! (Packet #%d) ---\n", current_packet_number);
    fprintf(output_file, "Length: %d bytes\n", header->len);

    // 1. Ethernet Header
    if (header->len < ETHER_HDR_LEN) {
        fprintf(output_file, "  [!] Packet too short for Ethernet header.\n");
        fflush(output_file);
        return;
    }
    struct eth_header *ethernet = (struct eth_header *)(packet);

    fprintf(output_file, "Ethernet Header:\n");
    print_mac(output_file, "\tSource MAC", ethernet->ether_shost);
    print_mac(output_file, "\tDestination MAC", ethernet->ether_dhost);

    u_char broadcast_mac[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (memcmp(ethernet->ether_dhost, broadcast_mac, ETHER_ADDR_LEN) == 0) {
        fprintf(output_file, "\t[+] Packet is BROADCAST Packet (ff:ff:ff:ff:ff:ff)\n");
        ethernet_broadcast_packets++;
    }

    u_short ether_type = ntohs(ethernet->ether_type);
    fprintf(output_file, "\tEtherType: 0x%04x ", ether_type);

    // Dispatch to next layer parser based on EtherType
    if (ether_type == ETHERTYPE_IP) {
        parse_ip_packet(output_file, packet, ETHER_HDR_LEN, header->len);
    }
    else if (ether_type == ETHERTYPE_ARP) {
        parse_arp_packet(output_file, packet, ETHER_HDR_LEN, header->len);
    }
    else {
        other_ether_packets++;
        fprintf(output_file, "(Other Ethernet Type: 0x%04x)\n", ether_type);
    }

    fflush(output_file);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_t *handle;
    pcap_dumper_t *pcap_dumper;
    FILE *text_output_file;
    sniffer_args_t args;

    char *selected_device_name = NULL;

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Display and Select Device
    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found. Exiting.\n");
        return 1;
    }

    selected_device_name = alldevs->name; // Store the selected device name

    printf("Sniffing on device: %s\n", selected_device_name);

    handle = pcap_open_live(selected_device_name, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", selected_device_name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    struct bpf_program fp;
    // Set a BPF filter to capture specific packets
    char filter_exp[] = ""; // Filter for IP or ARP packets
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        pcap_freecode(&fp);
        return 1;
    }
    printf("Applied BPF filter: \"%s\"\n", filter_exp);


    pcap_dumper = pcap_dump_open(handle, "sample.pcap");
    if (pcap_dumper == NULL) {
        fprintf(stderr, "Error opening pcap dump file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        pcap_freecode(&fp);
        return 1;
    }
    printf("Saving raw packet data to sample.pcap...\n");

    text_output_file = fopen("parsed_data.txt", "w");
    if (text_output_file == NULL) {
        perror("Error opening text output file");
        pcap_dump_close(pcap_dumper);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        pcap_freecode(&fp);
        return 1;
    }
    printf("Saving parsed data to parsed_data.txt...\n");

    args.pcap_dumper = pcap_dumper;
    args.text_output_file = text_output_file;

    printf("Capturing 100 packets...\n");

    pcap_loop(handle, 100, packet_handler, (u_char *)&args);

    // --- Print Statistics Summary ---
    fprintf(text_output_file, "\n--- Capture Statistics --- \n");
    printf("\n--- Capture Statistics --- \n");
    fprintf(text_output_file, "Total Packets Captured: %d\n", total_packets_captured);
    printf("Total Packets Captured: %d\n", total_packets_captured);
    fprintf(text_output_file, "  Ethernet Broadcasts: %d\n", ethernet_broadcast_packets);
    printf("  Ethernet Broadcasts: %d\n", ethernet_broadcast_packets);
    fprintf(text_output_file, "  ARP Packets: %d\n", arp_packets);
    printf("  ARP Packets: %d\n", arp_packets);
    fprintf(text_output_file, "  IP Packets: %d\n", ip_packets);
    printf("  IP Packets: %d\n", ip_packets);
    fprintf(text_output_file, "    TCP Packets: %d\n", tcp_packets);
    printf("    TCP Packets: %d\n", tcp_packets);
    fprintf(text_output_file, "    UDP Packets: %d\n", udp_packets);
    printf("    UDP Packets: %d\n", udp_packets);
    fprintf(text_output_file, "    ICMP Packets: %d\n", icmp_packets);
    printf("    ICMP Packets: %d\n", icmp_packets);
    fprintf(text_output_file, "    Other IP Protocols: %d\n", other_ip_protocols);
    printf("    Other IP Protocols: %d\n", other_ip_protocols);
    fprintf(text_output_file, "  Other Ethernet Types: %d\n", other_ether_packets);
    printf("  Other Ethernet Types: %d\n", other_ether_packets);


    pcap_dump_close(args.pcap_dumper);
    printf("Raw packet data saved to sample.pcap\n");

    fclose(args.text_output_file);
    printf("Parsed data saved to parsed_data.txt\n");

    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    printf("\nCapture finished.\n");
    return 0;
}