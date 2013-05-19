#include "cra.h"

void initDevice()
{
    device.sll_family = AF_PACKET;
    device.sll_halen = htons (6);
	 
    bzero(&sendDev,sizeof(sendDev));    
    sendDev.sll_family = AF_PACKET;
    sendDev.sll_halen = htons (ETH_ALEN);
    sendDev.sll_hatype = ARPHRD_ETHER;
    sendDev.sll_pkttype = PACKET_HOST;
    sendDev.sll_protocol = htons(ETH_P_ALL);
}

int initSocket()
{
    //Create the socket that listening to all packets
    s_dhcp = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s_dhcp < 0)
    {
        printf("[4over6 CRA]: Failed to create listening socket.\n");
        return -1;
    }

    //Create the socket that send back DHCPv4 packets
    s_send = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if (s_send < 0)
    {
        printf("[4over6 CRA]: Failed to create send socket.\n");
        return -1;
    }
	 
    //Create the socket that send out DHCPv4-over-v6 packets
    s_send6 = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (s_send6 < 0)
    {
        printf("[4over6 CRA]: Failed to create send socket.\n");
        return -1;
    }
    return 1;
}

void closeSocket()
{
    close(s_dhcp);
    close(s_send);
    close(s_send6);
}

int sendProxyArp(struct arppkt *recvArpPkt)
{
    struct arppkt *sendArpPkt=createArpResponse(recvArpPkt);
    //set the sockaddr_ll
    sendDev.sll_ifindex=recvDev.sll_ifindex;;
    memcpy(sendDev.sll_addr,sendArpPkt->etherpart.ether_dhost,ETH_ALEN);
    if (sendto(s_send,sendArpPkt, sizeof(struct arppkt), 0,(struct sockaddr *) &sendDev, sizeof(sendDev)) < 0)
    {
        perror(" Failed to send out reply packet.\n");
        return -1;
    }else{
        //printf("send successfully!\n");
    }
    free(sendArpPkt);
    return 1;
}

int sendPacket4(char *ethhead, char *udphead, int udplen)
{
    int frame_len;
    char *frame = trans6to4(ethhead, udphead, udplen, &frame_len);
    //Send out packet
    int index;
   
    if (isLocal(udphead + 36)) {//HCRA
        if(setDevIndex("lo"))
        {
            free(frame);
            printf("Fail to set the index to lo.");
            return 1;
        }
    }
    else//not send to the host
    {
        if(isLinkcra == 1)
        {
            index=hostMAC2index(udphead+36);
            if(index<0)
            {
                printf("Warning! Recv a dhcp v6 package but can't find the interface!\n");
                return -1;
            }
            device.sll_ifindex=index;
        }
        else
        {
            free(frame);
            return -1;
        }
    }
    
	 
    if (sendto(s_send, frame, frame_len, 0, (struct sockaddr *)&device, sizeof(device)) < 0) {
        printf("[4over6 CRA]: Failed to send back dhcpv4 packet.\n");
        return 1;
    }

    free(frame);
    return 0;   
}

int sendPacket6(char* ethhead, char* udphead, int udplen)
{
    int frame_len;
    char *frame = trans4to6(ethhead, udphead, udplen, &frame_len);

    if (sendto(s_send6, frame, frame_len, 0, (struct sockaddr *)&remote_addr6, sizeof(remote_addr6)) < 0) {
        printf("[4over6 CRA]: Failed to send out dhcpv4-over-v6 packet.\n");
        return 1;
    }
    //printf("[4over6 CRA]:Send dhcpv4-over-v6 packet.\n");
    free(frame);
    return 0;
}

//Debuging function  =========================
int getFakeReply(void) // This function is to listen on IPv6 port 67, and then vanish the ICMPv6 Port-Unreachable message
{
    if (fork() == 0) {
        struct sockaddr_in6 sin6addr;
        int addr_len = sizeof (sin6addr);
        char buff[1024];
        sin6addr.sin6_family = AF_INET6;
        sin6addr.sin6_flowinfo = 0;
        sin6addr.sin6_port = htons(67);
        sin6addr.sin6_addr = in6addr_any;
        int s = socket(AF_INET6, SOCK_DGRAM, 0);
        if (bind(s, (struct sockaddr*)&sin6addr, sizeof(sin6addr)) == -1)
        {
            printf("[4over6 CRA]: Failed to bind fake v6listener to port 68.\n");
            //return 1;
            exit(-1);
        }
        //printf("Ready to get a Fake v6\n");    
        while (1) {
            int result = recvfrom(s, buff, 1024, 0, (struct sockaddr*)&sin6addr, &addr_len);
            //usleep(1000);
        }
        printf("child thread exits.\n");
        exit(-1);
    }
    printf("return.\n");
    return 0;
}

int getPacket()
{
	
    memset(buff,0,buffLen);
    //Get a packet from all the interfaces
    int result;
    int recvlen=sizeof(recvDev);
    result = recvfrom(s_dhcp, buff, buffLen, 0,(struct sockaddr *) &recvDev, &recvlen);
    if(result<0)
    {
        printf("fail to recv package!");
        return -1;
    }
	
}

int setDevIndex(char* devname)
{
    // Resolve the interface index.
    if ((device.sll_ifindex = if_nametoindex (devname)) == 0)
    {
        printf("[4over6 CRA]: Failed to resolve the index of %s.\n",devname);
        return 1;
    }
    //printf ("Index for interface %s is %i\n", devname, device.sll_ifindex);
    return 0;
}
