#include "cra.h"

void initTable()
{
    gateways=NULL;
    hostInfos=NULL;
    local_interfaces=NULL;
    init_interfaces();
}

void init_interfaces()
{
    struct if_nameindex *interfaces = if_nameindex(), *interface;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    for (interface = interfaces; interface && interface->if_index; interface++) {
        struct ifreq ifopt;
        memset(&ifopt, 0, sizeof(ifopt));
        strcpy(ifopt.ifr_name, interface->if_name);
        if (ioctl(fd, SIOCGIFHWADDR, &ifopt) == -1) {
            printf("[4over6 CRA]: Failed to get MAC address of %s\n", interface->if_name);
        } else {
            struct interface *local_interface = malloc(sizeof(struct interface));
            memset(local_interface, 0, sizeof(struct interface));
            strcpy(local_interface->if_name, interface->if_name);
            local_interface->if_index = interface->if_index;
            memcpy(local_interface->addr, ifopt.ifr_hwaddr.sa_data, ETH_ALEN);
            printf("\tlocal interface : %d %s %s", interface->if_index, interface->if_name, mac_to_str(local_interface->addr));
            local_interface->next = local_interfaces;
            local_interfaces = local_interface;
            if (strcmp(LCRA_IFNAME, interface->if_name) == 0) {
                printf(" LCRA");
                lcra_interface = local_interface;
            }
            printf("\n");
        }
    }
    if_freenameindex(interfaces);
    close(fd);    
}

int isLocal(char *mac_addr)
{
    struct interface *interface = local_interfaces;
    while (interface) {
        if (memcmp(mac_addr, interface->addr, ETH_ALEN) == 0)
            return interface->if_index;
        interface = interface->next;
    }
    return 0;
}

int gatewayExist(char *object)
{
    struct if_gateway* gateway;
    for(gateway=gateways;gateway!=NULL;gateway=gateway->next)
    {
        if(memcmp(object,gateway->gateway_addr,4)==0)return 1;
    }
    return 0;
}

int hostMAC2index(char *MACaddr)
{
    struct if_hostInfo *hostMAC;
    for(hostMAC=hostInfos;hostMAC!=NULL;hostMAC=hostMAC->next)
    {
        if(memcmp(hostMAC->hostMAC_addr,MACaddr,ETH_ALEN)==0)
            return hostMAC->if_index;
    }
    return -1;
}

int hostIP2index(char *IPaddr)
{
    struct if_hostInfo *hostIP;
    for(hostIP=hostInfos;hostIP!=NULL;hostIP=hostIP->next)
    {
        if(memcmp(hostIP->hostIP_addr,IPaddr,4)==0)
            return hostIP->if_index;
    }
    return -1;
}

char *index2ifaddr(int if_index)
{
    struct interface *local_interface;
    for(local_interface=local_interfaces;local_interface!=NULL;local_interface=local_interface->next)
    {
        if(if_index==local_interface->if_index)
        {
            return local_interface->addr;
        }
    }
    return NULL;
}

char *index2ifname(int if_index)
{
    struct interface *local_interface;
    for(local_interface=local_interfaces;local_interface!=NULL;local_interface=local_interface->next)
    {
        if(if_index==local_interface->if_index)
        {
            return local_interface->if_name;
        }
    }
    return NULL;
}

void updateHostMAC(char *dhcphead)
{
    char *hostMACaddr = dhcphead+28;
    struct if_hostInfo *hostMAC;
  
    //find whether the item is recorded
    for(hostMAC=hostInfos;hostMAC!=NULL;hostMAC=hostMAC->next)
    {
        if(memcmp(hostMACaddr,hostMAC->hostMAC_addr,ETH_ALEN)==0)
            return;
    }
	
    //add a new record
    hostMAC=(struct if_hostInfo*)malloc(sizeof(struct if_hostInfo));
    hostMAC->next=hostInfos;
    hostMAC->if_index=recvDev.sll_ifindex;
    memcpy(hostMAC->hostMAC_addr,hostMACaddr,ETH_ALEN);
    memset(hostMAC->hostIP_addr,0,4);
    memset(hostMAC->mask,0,4);
	
    hostInfos=hostMAC;   
    printf("[4over6 CRA]:Add a hostMAC record!\n");
    printf("%d\t%s\n",hostMAC->if_index,mac_to_str(hostMAC->hostMAC_addr));  
}

struct if_hostInfo * updateHostIP(unsigned char *dhcpHead)
{
    unsigned char *hostIP_addr = dhcpHead+16;
    unsigned char *hostMAC_addr = dhcpHead+28;
    struct if_hostInfo *hostInfo;

    for(hostInfo=hostInfos;hostInfo!=NULL;hostInfo=hostInfo->next)
    {
        if(memcmp(hostMAC_addr,hostInfo->hostMAC_addr,ETH_ALEN)==0)
        {
            unsigned char *dhcpOption=getDhcpOption(dhcpHead,0x01);
            dhcpOption+=2;
            memcpy(hostInfo->mask,dhcpOption,4);
            memcpy(hostInfo->hostIP_addr,hostIP_addr,4);
            //hostInfo->if_index=recvDev.sll_ifindex;
            printf("table: Add a new IP record!\n");
            printf("mac:%02X:%02X:%02X:%02X:%02X:%02X,IP: %d.%d.%d.%d,mask: %d.%d.%d.%d,index:%d\n",hostInfo->hostMAC_addr[0],hostInfo->hostMAC_addr[1],hostInfo->hostMAC_addr[2],hostInfo->hostMAC_addr[3],hostInfo->hostMAC_addr[4],hostInfo->hostMAC_addr[5],hostInfo->hostIP_addr[0],hostInfo->hostIP_addr[1],hostInfo->hostIP_addr[2],hostInfo->hostIP_addr[3],hostInfo->mask[0],hostInfo->mask[1],hostInfo->mask[2],hostInfo->mask[3],hostInfo->if_index);
            
            return hostInfo;
        }
    }
    printf("Warning! IP is assigned to a MAC address that's not recorded!");
    return NULL;
}

int addRoute(struct if_hostInfo* hostInfo)
{
    if(hostInfo==NULL)return;

    int skfd =socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd < 0)
    {
        perror("Failed to creat socket");
    }

    struct rtentry rt;
    char if_name[20];
    struct sockaddr_in dst;
    struct sockaddr_in genmask;

    bzero(&genmask,sizeof(struct sockaddr_in));
    genmask.sin_family = AF_INET;
    genmask.sin_addr.s_addr = inet_addr("255.255.255.255");

    bzero(&dst,sizeof(struct sockaddr_in));
    dst.sin_family = AF_INET;
    memcpy(&dst.sin_addr.s_addr,hostInfo->hostIP_addr,4);

    strcpy(if_name,index2ifname(hostInfo->if_index));

    memset(&rt, 0, sizeof(rt));
    rt.rt_metric = 2;
    rt.rt_flags = RTF_UP;	
    rt.rt_dev = if_name;
    rt.rt_dst = *(struct sockaddr*) &dst;
    rt.rt_genmask = *(struct sockaddr*) &genmask;
    if(ioctl(skfd, SIOCADDRT, &rt) < 0) 
    {
        perror("Error route add");
        return -1;
    }
    printf("add router successfully!\n");
    return 1;
}

void updateGateway(unsigned char *dhcphead)
{
    int i,n;
    struct if_gateway *gateway;
	
    unsigned char *dhcpOption=getDhcpOption(dhcphead,0x03);
    if(dhcpOption!=NULL)
    {
        dhcpOption++;
        n=*dhcpOption/4;
        dhcpOption++;
        for(i=0;i<n;i++)
        {            
            if(gatewayExist(dhcpOption+i*4)==0)//judge whether it already exists
            {
                gateway=(struct if_gateway *)malloc(sizeof(struct if_gateway));
                memcpy(gateway->gateway_addr,dhcpOption+i*4,4);
                gateway->next=gateways;
                gateways=gateway;
                printf("Add a new gateway %d:%2x %2x %2x %2x\n",i+1,dhcpOption[0],dhcpOption[1],dhcpOption[2],dhcpOption[3]);
            }
        }	 
    }
}

int inSameLogicSubnet(unsigned char *ip1, unsigned char *ip2)
{
    struct if_hostInfo *hostIP;
    int i;
	
    for(hostIP=hostInfos;hostIP!=NULL;hostIP=hostIP->next)
    {
        if(memcmp(hostIP->hostIP_addr,ip1,4)==0)
        {
            for(i=0;i<4;i++)
            {
                if( (*(ip1+i)&&hostIP->mask) != (*(ip2+i)&&hostIP->mask))
                    return 0;
            }
            return 1;
        }
    }

    for(hostIP=hostInfos;hostIP!=NULL;hostIP=hostIP->next)
    {
        if(memcmp(hostIP->hostIP_addr,ip2,4)==0)
        {
            for(i=0;i<4;i++)
            {
                if( (*(ip1+i)&&hostIP->mask) != (*(ip2+i)&&hostIP->mask))
                    return 0;
            }
            return 1;
        }
    }
    //printf("warning! Can't find the mask of IP1 or IP2!\n");
	
    return -1;
}


int inSamePhysicalSubnet(unsigned char *ip1, unsigned char *ip2)
{
    int index2=hostIP2index(ip2);

    if(index2!= -1 && recvDev.sll_ifindex==index2)
        return 1;
    return 0;
}
