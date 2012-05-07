/**********************************************************************
 * file: pcap next.c
 * date: 25-Abril-2005
 * Author: Alejandro Lopez Monge
 * 
 * Compilacion: gcc -lpcap -o pcap_next pcap next.c
 * 
 * Ejemplo de como capturar un unico paquete usando pcap_next
 * **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
int main(int argc, char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    u_char *ptr;    //Contenedor del paquete

    if((dev = pcap_lookupdev(errbuf))==NULL) //buscamos un dispositivo
    {printf(" %s\n",errbuf);exit(1);}
    printf("Abriendo: %s\n",dev);

    if((descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf)) == NULL) 
        //abrimos un descriptor
        {printf("pcap_open_live(): %s\n", errbuf);exit(1);}
    if((packet = pcap_next(descr,&hdr))==NULL) 
        //capture the next packet
        {printf("Error\n");exit(-1);}

    printf("Capturado paquete de tamano %d\n", hdr.len);
    printf("Recibido a las %s\n",ctime((const time_t*)&hdr.ts.tv_sec));

    return 0;
}
