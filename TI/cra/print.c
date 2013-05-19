#include "cra.h"

char* mac_to_str(unsigned char *ha)
{
    int i;  
    static char macstr_buf[18] = {'\0', };    
    memset(macstr_buf, 0x00, 18);   
    for ( i = 0 ; i < ETH_ALEN ; i++) {  
        hexNumToStr(ha[i],&macstr_buf[i*3]);  
        if ( i < 5 ) {  
            macstr_buf[(i+1)*3-1] = ':';  
        }  
    }  
    return macstr_buf; 
}

void hexNumToStr(unsigned int number, char *str)  
{  
    char * AsciiNum={"0123456789ABCDEF"};        
    str[0]=AsciiNum[(number>> 4)&0xf];  
    str[1]=AsciiNum[number&0xf];  
}

void printMAC(unsigned char *mac)
{
    int i;
    printf("MAC: ");
    for(i =0 ; i < 6; i++)
    {
        printf("%02X\n", *(mac+i));
        if(i != 5)printf(":");
    }
    printf("\n");
}

void printIP(unsigned char *IP)
{
    int i;
    printf("IP:  ");
    for(i = 0; i < 4; i++)
    {
        printf("%d\n", *(IP+i));
        if(i!=3)printf(".");
    }
    printf("\n");
}
