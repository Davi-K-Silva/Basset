#ifndef BASSET_H
#define BASSET_H

/* Ethernet ARP packet from RFC 826 */
struct arp_hdr{
   uint16_t htype;   /* Format of hardware address */
   uint16_t ptype;   /* Format of protocol address */
   uint8_t hlen;    /* Length of hardware address */
   uint8_t plen;    /* Length of protocol address */
   uint16_t op;    /* ARP opcode (command) */
   uint8_t sha[ETH_ALEN];  /* Sender hardware address */
   uint32_t spa;   /* Sender IP address */
   uint8_t tha[ETH_ALEN];  /* Target hardware address */
   uint32_t tpa;   /* Target IP address */
}  __attribute__((packed)) arp_ether_ipv4;

const char* tblHeader = "PROT | Source         | Destination      | Size   | Info";

void printPackage(char[]);
void int32toipv4(u_int32_t, char*);

void ARP_pkg(char[]);
void IPv4_pkg(char[]);
void IPv6_pkg(char[]);
void ICMP_pkg(char[]);
void ICMP6_pkg(char[],int);
void TCP_pkg(char[],int);
void UDP_pkg(char[],int);

void printStats();

#endif