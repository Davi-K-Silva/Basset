/*-------------------------------------------------------------*/
/* Basset Sniffer */
/*-------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */
#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/ip.h> // ip header
#include <netinet/ip_icmp.h> //icmp header
#include <netinet/icmp6.h> //icmp header
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP
#include <netinet/in_systm.h> //tipos de dados
#include <net/if_arp.h> // Arp
#include <netinet/udp.h>	//Provides declarations for udp header
//#define __USE_MISC
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip6.h>

#include"Basset.h"

#define BUFFSIZE 1518

unsigned char buff1[BUFFSIZE]; // buffer de recepcao

int sockd;
int on;
struct ifreq ifr;
struct sockaddr_in source, dest;

//Info dos pacotes
int pkg_c = 0;
int sum_pck_size = 0;
float mean_pck_size = 0;
int max_pck_size = 0;
int min_pck_size = 0;

//Contadores protocolos
int ipv4_c = 0;
int ipv6_c = 0;
int arp_c = 0;
int arp_req_c = 0;
int arp_rep_c = 0;
int icmp_c = 0;
int icmp_req_c = 0;
int icmp_rep_c = 0;
int icmp6_c = 0;
int icmp6_req_c = 0;
int icmp6_rep_c = 0;
int udp_c = 0;
int tcp_c = 0;

int dns_c = 0;
int dhcp_c = 0;
int http_c = 0;
int https_c = 0;

int line = 1;
int max_pkg = 50;

void in6_addrtoipv6(const struct in6_addr*, char[]);
void printName();

int dataSize;

int main( int argc, char *argv[]) {

    if( argc > 3 || argc < 3 ) {
        printf("Usage: sudo ./basset [Network Interface] [N Packages]");
        exit(0);
    }

    max_pkg = atoi(argv[2]);
    char item[150];

    printName();

    printf("%s\n", tblHeader);

    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, argv[1]);
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	//int dataSize;

    // Package read
    while(pkg_c < max_pkg){

        dataSize = recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		pkg_c++;
		sum_pck_size += dataSize;
		mean_pck_size = sum_pck_size/pkg_c;
		if(dataSize > max_pck_size){
			max_pck_size = dataSize;
		}
		if(dataSize < min_pck_size || min_pck_size ==0){
			min_pck_size = dataSize;
		}


        char entry[150];
		if(buff1[12]==0x08 && buff1[13]==0x06){
			ARP_pkg(entry);
		} else if(buff1[12]==0x08 && buff1[13]==0x00){
            IPv4_pkg(entry);
		} else if(buff1[12]==0x86 && buff1[13]==0xdd){
			IPv6_pkg(entry);
		} else{
            sprintf(entry, "%-6s %-17s %-17s %-7d %-17s", "Other", "---", "---", dataSize, "---");
            printPackage(entry);
			// printf("%x%x\n",buff1[12],buff1[13]);
		}
    }

    printStats();
}

// ARP ----------------------------------------------------------------------------------------------- //
void ARP_pkg(char entry[]){
    arp_c++;

    struct arp_hdr *arp = (struct arp_hdr*) (buff1+14);
    
    char t[12];
    if(arp->op==256){
        strcpy(t,"Request");
        arp_req_c++;
    } else 
    if (arp->op==512){
        strcpy(t,"Reply");
        arp_rep_c++;
    }

    char ipsrc[32];
    int32toipv4(arp->spa, ipsrc);
    char ipdst[32];
    int32toipv4(arp->tpa, ipdst);
    
    // sprintf(entry, "%-7s       %-20s    %-20s","ARP" , inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
    sprintf(entry, "%-6s %-17s %-17s %-7d %s", "ARP", ipsrc, ipdst, dataSize, t);
    printPackage(entry);
}

// IPv4 ---------------------------------------------------------------------------------------------- //
void IPv4_pkg(char entry[]){
    ipv4_c++;

    struct iphdr *iph = (struct iphdr*) (buff1+14);

    char prompt[7];
    char info [70];

    memset(&info,0,sizeof(info));
    if(iph->protocol==1){
        sprintf(prompt,"%s","ICMP");
        ICMP_pkg(info);
    } else 
    if(iph->protocol==17){
        sprintf(prompt,"%s","UDP");
        UDP_pkg(info, (iph->ihl*4) + 14);
    } else
    if(iph->protocol==6){
        sprintf(prompt,"%s","TCP");
        TCP_pkg(info, (iph->ihl*4) + 14);
    }
    else{
        sprintf(prompt,"%d",iph->protocol);
    }   
    
    char ipsrc[32];
    int32toipv4(iph->saddr, ipsrc);
    char ipdst[32];
    int32toipv4(iph->daddr, ipdst);
    
    sprintf(entry, "%-6s %-17s %-17s %-7d %-17s", prompt, ipsrc, ipdst, dataSize, info);
    printPackage(entry);

}

// IPv6 ---------------------------------------------------------------------------------------------- //
void IPv6_pkg(char entry[]){
    ipv6_c++;

    struct ip6_hdr *ip6h = (struct ip6_hdr*) (buff1+14);

    char prompt[7];
    char info [70];

    memset(&info,0,sizeof(info));
    if(ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17){
        sprintf(prompt,"%s","UDP");
        UDP_pkg(info,ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen/256 + 14);
    } else
    if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6){
        sprintf(prompt,"%s","TCP");
        TCP_pkg(info,ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen/256 + 14);
    } else 
    if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58){
        sprintf(prompt,"%s","ICMP6");
        ICMP6_pkg(info,ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen/256 + 14);
    } else 
    if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 43){
        sprintf(prompt,"%s","ROUT");
    } else{
        sprintf(prompt,"%d",ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    }

    char ipsrc6[64];
    memset(&ipsrc6,0,sizeof(ipsrc6));
    inet_ntop(AF_INET6,&ip6h->ip6_src,ipsrc6,sizeof(ipsrc6));

    char ipdst6[64];
    memset(&ipdst6,0,sizeof(ipdst6));
    inet_ntop(AF_INET6,&ip6h->ip6_dst,ipdst6,sizeof(ipdst6));

    char rsrc[16];
    memset(rsrc,0,sizeof(rsrc));
    strncpy(rsrc,ipsrc6,12);
    if(strlen(ipsrc6) > 12){
        strcat(rsrc,"...");
    }
    
    
    char rdst[16];
    memset(rdst,0,sizeof(rdst));
    strncpy(rdst,ipdst6,12);
    if(strlen(ipdst6) > 12){
        strcat(rdst,"...");
    }

    sprintf(entry, "%-6s %-17s %-17s %-7d %-17s", prompt, rsrc, rdst,dataSize, info);
    printPackage(entry);

}

// ICMP ---------------------------------------------------------------------------------------------- //
void ICMP_pkg(char entry[]){
    icmp_c++;

    struct iphdr *iph = (struct iphdr *) (buff1+14);
	
	struct icmphdr *icmph = (struct icmphdr *) (buff1+ (iph->ihl*4) + 14);

    char t[12];
    if(icmph->type==ICMP_ECHO){
        strcpy(t,"Request");
        icmp_req_c++;
    } else 
    if (icmph->type==ICMP_ECHOREPLY){
        strcpy(t,"Reply");
        icmp_rep_c++;
    }
    
    strcpy(entry, t);
}

// ICMP6 --------------------------------------------------------------------------------------------- //
void ICMP6_pkg(char entry[],int prevLen){
    icmp6_c++;

    struct ip6_hdr *ip6h = (struct ip6_hdr*) (buff1+14);
	
	struct icmp6_hdr *icmp6h = (struct icmp6_hdr *) (buff1+prevLen);

    char t[12];
    if(buff1[54]==0x80){
        strcpy(t,"Request");
        icmp6_req_c++;
    } else 
    if (buff1[54]==0x81){
        strcpy(t,"Reply");
        icmp6_rep_c++;
    }

    strcpy(entry, t);
}

// UDP ----------------------------------------------------------------------------------------------- //
void UDP_pkg(char info[],int prevLen){
    udp_c++;
    
    //struct iphdr *iph = (struct iphdr *) (buff1+14);
    struct udphdr *udph = (struct udphdr *) (buff1 + prevLen);

    if(buff1[prevLen] == 0x00 && buff1[prevLen+1] == 0x35){
        sprintf(info,"%s->","DNS");
    } else 
    if(buff1[prevLen] == 0x00 && buff1[prevLen+1] == 0x43){
      sprintf(info,"%s->","DHCP");  
    } else 
    if(buff1[prevLen] == 0x00 && buff1[prevLen+1] == 0x44){
      sprintf(info,"%s->","DHCP");  
    }else {
      sprintf(info,"%u->",(((unsigned int)buff1[prevLen]<<8) | (unsigned int)buff1[prevLen+1]));
    }

    char def[20];
    if(buff1[prevLen+2] == 0x00 && buff1[prevLen+3] == 0x35){
        strcat(info,"DNS");
        dns_c++;
    } else 
    if(buff1[prevLen+2] == 0x00 && buff1[prevLen+3] == 0x43){
        strcat(info,"DHCP");
        dhcp_c++;
    } else 
    if(buff1[prevLen+2] == 0x00 && buff1[prevLen+3] == 0x44){
        strcat(info,"DHCP");
        dhcp_c++;  
    } else {
        sprintf(def,"%u",(((unsigned int)buff1[prevLen+2]<<8) | (unsigned int)buff1[prevLen+3]));
        strcat(info,def);
    }
    
}

// TCP ----------------------------------------------------------------------------------------------- //
void TCP_pkg(char info[],int prevLen){
    tcp_c++;

    struct iphdr *iph = (struct iphdr *) (buff1+14);
	
    struct tcphdr *tcph = (struct tcphdr*) (buff1+ prevLen );

    if(buff1[prevLen] == 0x00 && buff1[prevLen+1] == 0x50){
        sprintf(info,"%s->","HTTP");
    } else 
    if(buff1[prevLen] == 0x01 && buff1[prevLen+1] == 0xbb){
        sprintf(info,"%s->","HTTPS");  
    } else 
    if(buff1[prevLen] == 0x00 && buff1[prevLen+1] == 0x35){
        sprintf(info,"%s->","DNS");  
    }else {
      sprintf(info,"%u->",(((unsigned int)buff1[prevLen]<<8) | (unsigned int)buff1[prevLen+1]));
    }

    char def[20];
    if(buff1[prevLen+2] == 0x00 && buff1[prevLen+3] == 0x50){
        strcat(info,"HTTP");
        http_c++;
    } else 
    if(buff1[prevLen+2] == 0x01 && buff1[prevLen+3] == 0xbb){
        strcat(info,"HTTPS");
        https_c++;
    } else 
    if(buff1[prevLen+2] == 0x00 && buff1[prevLen+3] == 0x35){
        strcat(info,"DNS");
        dns_c++;  
    } else {
        sprintf(def,"%u",(((unsigned int)buff1[prevLen+2]<<8) | (unsigned int)buff1[prevLen+3]));
        strcat(info,def);
    }
    
}

 
// Aux ----------------------------------------------------------------------------------------------- //
void int32toipv4(u_int32_t ip_int, char* ip){
    unsigned char bytes[4];
    bytes[0] =  ip_int & 0xFF;
    bytes[1] = (ip_int >> 8) & 0xFF;
    bytes[2] = (ip_int >> 16) & 0xFF;
    bytes[3] = (ip_int >> 24) & 0xFF;   
    sprintf(ip,"%d.%d.%d.%d",bytes[0],bytes[1],bytes[2],bytes[3]);
}

void in6_addrtoipv6(const struct in6_addr *addr, char *ip6) {
   sprintf(ip6, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                 (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                 (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                 (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                 (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                 (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                 (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                 (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

void printStats(){
    printf("\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    printf("Mean: %.1f B | Max: %d B | Min: %d B \n",mean_pck_size,max_pck_size,min_pck_size);
	printf("Ipv4:  %-3d | %-3.1f% \n",ipv4_c, ipv4_c*100.0/pkg_c);
    printf("Ipv6:  %-3d | %-3.1f% \n",ipv6_c, ipv6_c*100.0/pkg_c);
    printf("ARP:   %-3d | %-3.1f% | Req: %-2d | Rep: %-2d \n",arp_c, arp_c*100.0/pkg_c, arp_req_c, arp_rep_c);
    printf("ICMP:  %-3d | %-3.1f% | Req: %-2d | Rep: %-2d \n",icmp_c, icmp_c*100.0/pkg_c, icmp_req_c, icmp_rep_c);
    printf("ICMP6: %-3d | %-3.1f% | Req: %-2d | Rep: %-2d \n",icmp6_c, icmp6_c*100.0/pkg_c, icmp6_req_c, icmp6_rep_c);
    printf("UDP:   %-3d | %-3.1f% \n",udp_c, udp_c*100.0/pkg_c);
    printf("TCP:   %-3d | %-3.1f% \n",tcp_c, tcp_c*100.0/pkg_c);
    printf("DNS:   %-3d | %-3.1f% \n",dns_c, dns_c*100.0/pkg_c);
    printf("DHCP:  %-3d | %-3.1f% \n",dhcp_c, dhcp_c*100.0/pkg_c);
    printf("HTTP:  %-3d | %-3.1f% \n",http_c, http_c*100.0/pkg_c);
    printf("HTTPS: %-3d | %-3.1f% \n",https_c, https_c*100.0/pkg_c);
	printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}

void printPackage(char info[]){
    char item[100];
    sprintf(item, "%-7s",  info);
    printf( "%s\n", item );
}

void printName(){
printf("            __\n");              
printf("(\\,--------'()'--o\n");
printf(" (_    ___  ()/~´    SNIFF... SNIFF...\n");
printf("  (_)_)  (_)_)\n");
}
