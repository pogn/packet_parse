#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
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
        u_int8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_int8_t  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        uint16_t ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header{
        u_int8_t ip_vhl;                 /* version << 4 | header length >> 2 */
        u_int8_t ip_tos;                 /* type of service */
        uint16_t ip_len;                 /* total length */
        uint16_t ip_id;                  /* identification */
        uint16_t ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_int8_t  ip_ttl;                 /* time to live */
        u_int8_t  ip_p;                   /* protocol */
        uint16_t ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
        uint16_t th_sport;               /* source port */
        uint16_t th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_int8_t  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_int8_t  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        uint16_t th_win;                 /* window */
        uint16_t th_sum;                 /* checksum */
        uint16_t th_urp;                 /* urgent pointer */
};

int main(int argc, char *argv[])
    {
       setbuf(stdout, NULL);
       pcap_t *handle;			/* Session handle */
       char *dev;			/* The device to sniff on */
       char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
       struct bpf_program fp;		/* The compiled filter */
       char filter_exp[] = "port 80";	/* The filter expression */
       bpf_u_int32 mask;		/* Our netmask */
       bpf_u_int32 net;		/* Our IP */
       struct pcap_pkthdr *header;	/* The header that pcap gives us */
       const u_int8_t *packet;	/* The actual packet */
       int res,i,k,num;
       struct ethernet_header *pEth;
       struct ip_header *pIph;
       struct tcp_header *pTcp;
       int len;

       /* Define the device */
       //dev = pcap_lookupdev(errbuf);
       //if (dev == NULL) {
       //    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       //    return(2);
       //}

       /* Find the properties for the device */
       if (!argv[1]){
           fprintf(stderr,"Please input the device name");
       }
       dev=argv[1];
       if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
           fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
           net = 0;
           mask = 0;
       }

       /* Open the session in promiscuous mode */
       handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //dev --> "dum0"
       if (handle == NULL) {
           fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
           return(2);
       }

       /* make error when the port num is not 80
       // Compile and apply the filter
       if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
           fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }
       if (pcap_setfilter(handle, &fp) == -1) {
           fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }
       */

/* Grab a packet */
       num=0;
       printf("-----------grabbing 10 packets------------------\n");
       printf("grabbing 10 packets\n");

       while((res = pcap_next_ex(handle, &header, &packet))>=0){ //double pointer
           if(res==0) {continue;}
           num++;
           if(num ==10)
               break;
       //}

       /* Print its length */
       printf("Length [%d]\n", header->len);

       /* print packet data*/
       pEth = (struct ethernet_header *)packet;
       pIph = (struct ip_header *)(packet + sizeof(*pEth));
       pTcp = (struct tcp_header *)(packet + sizeof(*pEth) + sizeof(*pIph));

       /* check IP and TCP and port num */
       if(pEth->ether_type!=0x0008){
           fprintf(stderr, "-----------------------This is not IP packet----------------------");
           continue;
       }
       if(pIph->ip_p != 0x06){
           fprintf(stderr, "-----------------------This is not TCP packet---------------------");
           continue;
       }

       /* print ehternet */
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
       char tmp[INET_ADDRSTRLEN];
       inet_ntop(AF_INET, &(pIph->ip_src), tmp, INET_ADDRSTRLEN);
       fprintf(stdout, "SOURCE IP address       - [%s]\n", tmp); //inet_ntoa(pIph->ip_src));
       inet_ntop(AF_INET, &(pIph->ip_dst), tmp, INET_ADDRSTRLEN);
       fprintf(stdout, "DESTINATION IP address  - [%s]\n", tmp);//inet_ntoa(pIph->ip_dst));

// print TCP
       fprintf(stdout, "SOURCE port             - [%hu]\n", ntohs(pTcp->th_sport)); //recommandation - befor using %hu, print "%02x" to see real hex value
       fprintf(stdout, "DESTINATION port        - [%hu]\n", ntohs(pTcp->th_dport)); //without ntohs, it will read memory "little endian"

// print Data
       fprintf(stdout,"DATA\n");
       len=ntohs(pIph ->ip_len);
       for(i = sizeof(*pEth) + sizeof(*pIph) + sizeof(*pTcp) ; i < len ; i+=16)
       {
          fprintf(stdout, "[%08x] ", i-(sizeof(*pEth) + sizeof(*pIph) + sizeof(*pTcp)));
          for(k = 0 ; k < 16  ; ++k)
          {
              if( k + i < header->len )
                  fprintf(stdout, "%02X",*((u_char*)packet + k + i ));
              if( k ==8 )
                  fprintf(stdout, " ");
              else
                  fprintf(stdout," ");
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
    printf("-------------------------------------------------\n");
}
       /* And close the session */
       pcap_close(handle);
       return(0);
}
