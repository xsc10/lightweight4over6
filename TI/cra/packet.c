#include "cra.h"

unsigned char* getDhcpOptions(unsigned char *dhcpHead)
{
    return dhcpHead+240;
}


unsigned char *getDhcpOption(unsigned char *dhcpHead, unsigned char type)
{
    unsigned char *dhcpOption;
    dhcpOption=getDhcpOptions(dhcpHead);
    while(*dhcpOption!=0xFF)
    {
        if(*dhcpOption==type)
        {
            return dhcpOption;  
        }
        dhcpOption++;
        dhcpOption+=(*dhcpOption+1);
    }
    return NULL;
}

int isUDPpacket(char* iphead, int type)
{
    switch (type)
    {
    case 4:
        if (iphead[9] != IPPROTO_UDP)
        {
            //printf("[4over6 CRA]: Got a v4 packet but is not UDPv4.\n");
            return 0;
        }
        break;
    case 6:
        if (iphead[6] != IPPROTO_UDP)
        {
            //printf("[4over6 CRA]: Got a v6 packet but is not UDPv6.\n");
            return 0;
        }
        break;
    default:
        //printf("[4over6 CRA]: Wrong argument of isUDPpacket.\n");
        return 0;
        break;
    }
    return 1;    
}

int isDHCPpacket(int type, char* udphead)
{
    uint16_t src_port = ntohs(*(uint16_t*)(udphead + 0));
    uint16_t dst_port = ntohs(*(uint16_t*)(udphead + 2));
//printf("src_port = %d, dst_port = %d\n",src_port, dst_port);
    if (type == 4) {
        if (dst_port != 67 /*|| src_port != 68*/)
        {
            //printf("[4over6 CRA]: Got a packet but not targeted to port %d.\n",dst);
            return 0;
        }  
    }
    if (type == 6) {
        if (dst_port != 67 || src_port != 67)
        {
            //printf("[4over6 CRA]: Got a packet but not targeted to port %d.\n",dst);
            return 0;
        }  
    }

    return 1;
}

int isDHCPAck(unsigned char *dhcpHead)
{
    unsigned char *dhcptype=getDhcpOption(dhcpHead,0x35);
    if(dhcptype==NULL)return 0;
  
    if(*(dhcptype+2)==0x05)return 1;
    return 0;   
}

unsigned short int
checksum (unsigned short int *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short int *w = addr;
    unsigned short int answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= sizeof (unsigned short int);
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

uint16_t udpchecksum(char *iphead, char *udphead, int udplen, int type)
{
    udphead[6] = udphead[7] = 0;
    uint32_t checksum = 0;
    //printf("udp checksum is 0x%02x%02x\n", (uint8_t)udphead[6], (uint8_t)udphead[7]);
    if (type == 6)
    {
        struct udp6_psedoheader header;
        memcpy(header.srcaddr, iphead + 24, 16);
        memcpy(header.dstaddr, iphead + 8, 16);
        header.length = ntohs(udplen);
        header.zero1 = header.zero2 = 0;
        header.next_header = 0x11;
        uint16_t *hptr = (uint16_t*)&header;
        int hlen = sizeof(header);
        while (hlen > 0) {
            checksum += *(hptr++);
            hlen -= 2;
        }
    }
    else if (type == 4)
    {
        struct udp4_psedoheader header;
        memcpy((char*)&header.srcaddr, iphead + 12, 4);
        memcpy((char*)&header.dstaddr, iphead + 16, 4);
        header.zero = 0;
        header.protocol = 0x11;
        header.length = ntohs(udplen);
        uint16_t *hptr = (uint16_t*)&header;
        int hlen = sizeof(header);
        while (hlen > 0) {
            checksum += *(hptr++);
            hlen -= 2;
        }
    }    
    uint16_t *uptr = (uint16_t*)udphead;
    while (udplen > 1) {    
        checksum += *(uptr++);
        udplen -= 2;
    }
    if (udplen) {
        checksum += (*((uint8_t*)uptr)) ;
    }
    do {
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    } while (checksum != (checksum & 0xFFFF));
    uint16_t ans = checksum;
    return (ans == 0xFF)? 0xFF :ntohs(~ans);
}

struct arppkt *createArpResponse(struct arppkt *recvArpPkt)
{
    //construct the arp package to be sent
    int index=recvDev.sll_ifindex;
    struct arppkt *sendArpPkt=(struct arppkt*)malloc(sizeof(struct arppkt));
    memcpy(sendArpPkt->etherpart.ether_dhost,recvArpPkt->etherpart.ether_shost,ETH_ALEN);
    memcpy(sendArpPkt->etherpart.ether_shost,index2ifaddr(index),ETH_ALEN);
    memcpy(&sendArpPkt->etherpart.ether_type,&recvArpPkt->etherpart.ether_type,2);
    sendArpPkt->arppart.ar_hrd=recvArpPkt->arppart.ar_hrd;
    sendArpPkt->arppart.ar_pro=recvArpPkt->arppart.ar_pro;
    sendArpPkt->arppart.ar_hln=recvArpPkt->arppart.ar_hln;
    sendArpPkt->arppart.ar_pln=recvArpPkt->arppart.ar_pln;
    sendArpPkt->arppart.ar_op=htons(2);
    memcpy(sendArpPkt->arppart.ar_sha,sendArpPkt->etherpart.ether_shost,ETH_ALEN);
    memcpy(sendArpPkt->arppart.ar_sip,recvArpPkt->arppart.ar_tip,4);
    memcpy(sendArpPkt->arppart.ar_tha,recvArpPkt->arppart.ar_sha,ETH_ALEN);
    memcpy(sendArpPkt->arppart.ar_tip,recvArpPkt->arppart.ar_sip,4);
    return sendArpPkt;
}

char *trans6to4(char *ethhead, char *udphead, int udplen, int *frame_len)
{
    *(uint16_t*)(udphead + 2) = htons(68);
    char *frame = NULL;
    udplen += 40;
    *frame_len = 14 + 20 + udplen;
	
	 
    frame = malloc (sizeof(char) * (*frame_len));
    //Add ethernet header
    memcpy(frame, ethhead, 14);
    memcpy(frame, udphead + 36, 6);
    frame[12] = ETH_P_IP / 256;
    frame[13] = ETH_P_IP % 256;
    //Add ipv4 header
    send_ip4hdr.ip_hl = 5;
    send_ip4hdr.ip_v = 4;
    send_ip4hdr.ip_tos = 0;
    send_ip4hdr.ip_len = htons(20 + udplen);
    send_ip4hdr.ip_id = htons(0);
    send_ip4hdr.ip_off = htons(0);
    send_ip4hdr.ip_ttl = 255;
    send_ip4hdr.ip_p = IPPROTO_UDP;
    //ciaddr is from yiaddr field
    memcpy(ciaddr,udphead + 24,4);
    inet_pton(AF_INET,"0.0.0.0",&siaddr);
    memcpy((char*)&send_ip4hdr.ip_dst,ciaddr,4);
    memcpy((char*)&send_ip4hdr.ip_src,siaddr,4);
    send_ip4hdr.ip_sum = 0;
    send_ip4hdr.ip_sum = checksum((unsigned short int*)&send_ip4hdr,20);
    memcpy(frame + 14,(char *)&send_ip4hdr, 20);

    //Re-caculate the udp checksum
    uint16_t newchecksum = udpchecksum((char*)&send_ip4hdr, udphead, udplen,4);
    udphead[6] = (newchecksum >> 8) & 0xFF;
    udphead[7] = newchecksum & 0xFF;
	 
    //Add udp header + dhcp data
    memcpy(frame + 14 + 20, udphead, udplen);
    memcpy(frame, udphead + 36, 6);
    return frame;
}


char *trans4to6(char *ethhead, char *udphead, int udplen, int *frame_len)
{
    char *frame = NULL;
    *frame_len = 40 + udplen;
    frame = malloc (sizeof(char) * (*frame_len));

    *(uint16_t*)udphead = htons(67);

    //Add ipv6 header
    send_ip6hdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);        
    send_ip6hdr.ip6_plen = htons(udplen);
    send_ip6hdr.ip6_nxt = IPPROTO_UDP;
    send_ip6hdr.ip6_hops = 128;
    inet_pton(AF_INET6,local6addr,&send_ip6hdr.ip6_src);
    inet_pton(AF_INET6,remote6addr,&send_ip6hdr.ip6_dst);    
    memcpy(frame, (char *)&send_ip6hdr, 40);

    //memcpy(udphead + 36, macaddr_phy, 6);
	 
    //Re-caculate the udp checksum
    uint16_t newchecksum = udpchecksum((char*)&send_ip6hdr, udphead, udplen,6);
    udphead[6] = (newchecksum >> 8) & 0xFF;
    udphead[7] = newchecksum & 0xFF;
    //Add udp header + dhcp data
    memcpy(frame + 40, udphead, udplen);
    return frame;
}

int getPacketType()
{
    int type = 0;
    //Locate the headers of the packet
    ethhead = buff;
    if (ethhead[0] == 0x45)// && ethhead[1] == 0x00) {
    {
        iphead = ethhead;
        type = 4;
        printf("Warning! Recv ipv4 packages without ethernet part.\n");
    }
    if(ethhead[12]==0x08&&ethhead[13]==0x06){
        //printf("arp\n");
        return 1;
    }
    if(ethhead[12]==0x08&&ethhead[13]==0x00){
        //printf("ipv4\n");
        iphead = ethhead + 14;
        udphead = iphead + 20;
        udplen = ((iphead[2]<<8)&0XFF00 | iphead[3]&0XFF) - 20;
        return 4;
    }
    if(ethhead[12]==0x86&&ethhead[13]==0xdd)
    {
        // printf("ipv6\n");
        iphead = ethhead + 14;
        udphead = iphead + 40;
        udplen = ((iphead[4]<<8)&0XFF00 | iphead[5]&0XFF) - 40;
        return 6;
    }
    //printf("head: %x %x\n",ethhead[12],ethhead[13]);
	

	 
    return type;
}
