#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct ethernet_header{
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

int main(int argc, char *argv[])
    {
       setbuf(stdout, NULL);
       printf("hi");
       pcap_t *handle;			/* Session handle */
       char *dev;			/* The device to sniff on */
       char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
       struct bpf_program fp;		/* The compiled filter */
       char filter_exp[] = "port 80";	/* The filter expression */
       bpf_u_int32 mask;		/* Our netmask */
       bpf_u_int32 net;		/* Our IP */
       struct pcap_pkthdr *header;	/* The header that pcap gives us */
       const u_char *packet;	/* The actual packet */
       int res,i,k;
       struct ethernet_header *pEth;
       struct ip_header *pIph;
       struct tcp_header *pTcp;

       printf("hi");
       /* Define the evice */
       dev = pcap_lookupdev(errbuf);
       if (dev == NULL) {
           fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
           return(2);
       }
       /* Find the properties for the device */
       if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
           fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
           net = 0;
           mask = 0;
       }
       /* Open the session in promiscuous mode */
       handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
       if (handle == NULL) {
           fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
           return(2);
       }
       /* Compile and apply the filter */
       if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
           fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }
       if (pcap_setfilter(handle, &fp) == -1) {
           fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }

       /* Grab a packet */
       printf("hi");
       while((res = pcap_next_ex(handle, &header, &packet))>=0){ //double pointer
           if(res==0) {printf("no");continue; }
           printf("yes\n");
           break;
       }

       /* Print its length */
       printf("Jacked a packet with length of [%d]\n", header->len);

       /* print packet data*/
       pEth = (struct ethernet_header *)packet;
       pIph = (struct ip_header *)(packet + sizeof(*pEth));
       pTcp = (struct tcp_header *)(packet + sizeof(*pEth) + sizeof(*pIph));

       //printf("packet : %s\n", pEth->ether_dhost);

       // print ehternet
       fprintf(stdout, "DESTINATION MAC Address - [");
       for( i = 0 ; i < 6 ; ++i)
       {
         fprintf(stdout, "%02X:", pEth->ether_dhost[i]);
       }
       fprintf(stdout, "\b]\t\t\n");

       fprintf(stdout, "SOURCE      MAC Address - [");
       for( i= 0 ; i < 6 ; ++i)
       {
         fprintf(stdout, "%02X:", pEth->ether_shost[i]);
       }
       fprintf(stdout, "\b]\n");

       // print IP
       fprintf(stdout, "SOURCE IP address       - [%s]\n", inet_ntoa(pIph->ip_src));
       fprintf(stdout, "DESTINATION IP address  - [%s]\n", inet_ntoa(pIph->ip_dst));

       // print TCP
       fprintf(stdout, "SOURCE port        -[%02x]\n", pTcp->th_sport);
       fprintf(stdout, "SOURCE port        -[%02x]\n", pTcp->th_dport);

       // print Data
       for(i = sizeof(*pEth) + sizeof(*pIph) + sizeof(*pTcp) ; i < header->len ; i+=16)
       {
          fprintf(stdout, "[%08x] ", i);
          for(k = 0 ; k < 16  ; ++k)
          {
              if( k + i < header->len )
                  fprintf(stdout, "%02X",*((u_char*)packet + k + i ));
              if( k ==8 )
                  fprintf(stdout, " ");
              else
                  fprintf(stdout," ");

          /*if(k == 8)
                fprintf(stdout, "  ");
            if((k + i) < len)
                fprintf(stdout, " %02X", * ((u_char*)packet + k + i));
            else
                fprintf(stdout, "   ");*/
         }
         printf(" | ");
         for(k = 0 ; k < 16  ; ++k)
         {
            if(k == 8)
                fprintf(stdout, " ");
            if((k + i) < header -> len)
            {
                if( ((*((u_char*)packet + k + i)) >= 33) && ((*((u_char*)packet+ k + i)) <= 126) )
                    fprintf(stdout, "%c", * ( (u_char*)packet + k + i) );
                else
                    printf(".");
            }
            else
            {
                printf(" ");
            }
        }
        printf("\n");
    }

       /* And close the session */
       pcap_close(handle);
       return(0);
    }
