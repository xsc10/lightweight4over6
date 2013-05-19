#include "cra.h"

static char firstAlpha(char *s);

int main(int argc, char **argv)
{
    buffLen = BUFFLEN;
    isLinkcra = 0;
   
    strcpy(local6addr,"2001:da8:bf:19::7");
    strcpy(remote6addr,"2001:da8:bf:19::3");
   
    //Read the arguments and operate
    int index = 2;
    if (argc < 2) {
        show_help();
        return 0;
    }
   
    while (index <= argc) {
        switch (firstAlpha(argv[index - 1])) {
        case 'a' ://set local6addr and remote6addr
            if (argc < index + 2) {
                printf("[4over6 CRA]: wrong number of arguments.\n");
                return 1;
            }
            strcpy(local6addr,argv[index]);
            strcpy(remote6addr,argv[index + 1]);
            index += 3;
            break;
        case 'b' ://set physic device name
            printf("warning : option -b is not used any more!\n");
            index += 2;
            break;
        case 'c' ://set tunnel device name
            printf("warning : option -c is not used any more!\n");
            index += 2;
            break;
        case 'd' ://run with default configuration
            if (index == 2) {
                printf("[4over6 CRA]:Continue with default configuration.\n");
                index = argc + 1;
            }
            index ++;
            break;
        case 'l' ://set LCRA device name
            printf("[4over6 CRA]:Run in link-cra mode.\n");
            isLinkcra = 1;
            index += 2;
            break;
        case 'h' ://help info
        default :
            show_help();
            return 0;
        } 
    }
    //Show current configuration
    printf("Local ipv6 address : %s\nRemote ipv6 address: %s\n",local6addr,remote6addr);

    inet_pton(AF_INET6,remote6addr,remote6addr_buf);	 
    remote_addr6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, remote6addr, &(remote_addr6.sin6_addr));

    initTable();	 
    initDevice();
    initSocket();
    printf("[4over6 CRA]: Listening...\n");
    getFakeReply();
    //CRA auto-machine
    int type;
    while (1) {
        getPacket();
        type= getPacketType();
        if (isLinkcra ==1 && type == 1)//recv an arp package
        {
            recvArpPkt=(struct arppkt *)buff;
            if(recvArpPkt->arppart.ar_op==htons(1))//recv a request arp package
            {	
                //printf("[4over6 CRA]:received an arp request package!\n");
                if(inSamePhysicalSubnet(recvArpPkt->arppart.ar_sip,recvArpPkt->arppart.ar_tip)!=1)
                {
                    //printf("[4over6 CRA]:send a proxy arp!");
                    sendProxyArp(recvArpPkt);	 
                } 
            }		   
        }
		
        if (type == 4) {
            //Find out the DHCP packet from 4over6 interface	
            if (isUDPpacket(iphead,4) && isDHCPpacket(4, udphead)) {
                //printf("[4over6 CRA]:receive an DHCP4 package!\n");
                //Send out DHCPv4-over-v6 packet
                uint8_t message_type = *(udphead + 8);
                if (message_type == 1) {
                    //printf("[4over6 CRA]:received an DHCP4 request package!\n");
                    if(isLinkcra == 1)
                    {
                        updateHostMAC(udphead+8);
                        sendPacket6(ethhead,udphead,udplen);		   
                    }
                    else //hostcra only handle packages send by local interfaces
                    {
                        if(isLocal(udphead+8+28)!=0)
                            sendPacket6(ethhead,udphead,udplen);
                    }
									
                }
            }
        } else if (type == 6) {
            //find out the DHCPv4-over-v6 packet from physic interface
            if (isUDPpacket(iphead,6) && isDHCPpacket(6, udphead)) {
                //Send back DHCPv4 packet to 4over6 interface.
                uint8_t message_type = *(udphead + 8);
                if (message_type == 2) {
                    //printf("[4over6 CRA]:received an DHCP6 ack package!\n");
                    sendPacket4(ethhead,udphead,udplen);
                    if(isLinkcra && isDHCPAck(udphead+8)) 
                    {
                        struct if_hostInfo * hostInfo=updateHostIP(udphead+8); 
                        if(hostInfo != NULL)
                            addRoute(hostInfo);
                    }				   
                }
            }
        }
    }
	  
    closeSocket();
    printf("[4over6 CRA]: Closed.\n");
    return 0;
}

static char firstAlpha(char *s)
{
    while (s && *s && *s == '-')
        s++;
    return s ? *s : 0;
}
//UI Function	 ===========================
void show_help(void)
{
    printf("Usage: cra [-d] | [-a <local_ipv6_addr> <remote_ipv6_addr>]\n");
    printf("		   [-l LCRA_ITERFACE_NAME]\n");
//	 printf("-h : display this help information.\n");
    printf("-d : run program with default settings.\n");
    printf("-a : set local and remote ipv6 address.\n");
    printf("-l : set the LCRA mode.\n");//the name of the local interface which runs LCRA.\n");
//	 printf("-b : set physic device (interface) name.\n");
//	 printf("-c : set the name of the interface on which runs the DHCP client.\n");
    return ;
}

