#ifndef CRA_H
#define CRA_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
//#include<arpa/inet.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
//#include <linux/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>  //IPPROTO_RAW,IPPROTO_UDP
#include <netinet/ip.h>  //struct ip
#include <netinet/ip6.h> //struct ip6_hdr
#include <net/if_arp.h>
#define BUFFLEN 1501

struct udp6_psedoheader {
    uint8_t srcaddr[16];
    uint8_t dstaddr[16];
    uint32_t length;
    uint16_t zero1;
    uint8_t zero2;
    uint8_t next_header;
};

struct udp4_psedoheader {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

struct interface {
    unsigned int if_index;
    char if_name[20];
    uint8_t addr[ETH_ALEN];
    struct interface *next;
};

struct if_gateway
{
    //unsigned int if_index;
    char gateway_addr[4];
    struct if_gateway *next;
};

struct if_hostInfo
{
    unsigned int if_index;
    unsigned char hostMAC_addr[ETH_ALEN];
    unsigned char hostIP_addr[4];
    unsigned char mask[4];
// unsigned int leaseTime;
    struct if_hostInfo *next;
};


struct myether_header
{
    u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
    u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
    u_int16_t ether_type;                 /* packet type ID field */
};

struct myarphdr
{
    unsigned short int ar_hrd;          /* Format of hardware address.  */
    unsigned short int ar_pro;          /* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;           /* ARP opcode (command).  */
    unsigned char ar_sha[ETH_ALEN];   /* Sender hardware address.  */
    unsigned char ar_sip[4];          /* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN];   /* Target hardware address.  */
    unsigned char ar_tip[4];          /* Target IP address.  */
};

struct arppkt
{
    struct myether_header etherpart;
    struct myarphdr arppart;
};


//char TUNNEL_IFNAME[20];
//char PHYSIC_IFNAME[20];
int isLinkcra;

char LCRA_IFNAME[20];
struct interface *lcra_interface;
struct if_gateway *gateways;
struct if_hostInfo *hostInfos;
struct interface *local_interfaces;

char buff[BUFFLEN];
int buffLen;
unsigned char *ethhead, *iphead, *udphead, *payload;
//struct myether_header *ether_head;
struct arppkt *recvArpPkt;
struct arppkt *sendArpPkt;

int udplen;
//char macaddr_4o6[6], macaddr_phy[6];
char local6addr[128], remote6addr[128];
char remote6addr_buf[16];

int s_dhcp, s_send, s_send6;
struct sockaddr_in6 remote_addr6, local_addr6;
char ciaddr[4], siaddr[4];
struct sockaddr_ll device;
struct sockaddr_ll recvDev;
struct sockaddr_ll sendDev;
struct ip send_ip4hdr;
struct ip6_hdr send_ip6hdr;

//about socket
void initDevice();
int initSocket();
void closeSocket();
int sendProxyArp(struct arppkt *recvArpPkt);
int sendPacket6(char*, char*, int);
int sendPacket4(char*, char*, int);

//about tables
void initTable();
int gatewayExist(char *);
int hostMAC2index(char *MACaddr);
int hostIP2index(char *IPaddr);
char *index2ifaddr(int if_index);
void updateHostMAC(char *dhcphead);
struct if_hostInfo * updateHostIP(unsigned char *dhcpHead);
void updateGateway(unsigned char *dhcphead);
int inSameLogicSubnet(unsigned char *ip1, unsigned char *ip2);
int inSamePhysicalSubnet(unsigned char *ip1, unsigned char *ip2);
void init_interfaces();
int isLocal(char *mac_addr);
int addRoute(struct if_hostInfo*);
char *index2ifname(int if_index);

//about packages
unsigned char* getDhcpOptions(unsigned char *dhcpHead);
unsigned char *getDhcpOption(unsigned char *dhcpHead, unsigned char type);
int isUDPpacket(char* iphead, int type);
int isDHCPpacket(int type, char*);
int isDHCPAck(unsigned char *dhcpHead);
unsigned short int checksum (unsigned short int*, int);
int setDevIndex(char *);
int getPacket( );
struct arppkt *createArpResponse(struct arppkt *recvArpPkt);
char *trans6to4(char *ethhead, char *udphead, int udplen, int *frame_len);
char *trans4to6(char *ethhead, char *udphead, int udplen, int *frame_len);
//int isDHCPACK(char*);
uint16_t udpchecksum(char *, char *, int, int);
int getPacketType();

//about print
char* mac_to_str(unsigned char *);
void hexNumToStr(unsigned int, char *);
void printMAC(unsigned char *mac);
void printIP(unsigned char *IP);
//UI Function
void show_help(void);

//Debugging Function
int getFakeReply(void); // This function is to listen on IPv6 port 67, and then vanish the ICMPv6 Port-Unreachable message




#endif
