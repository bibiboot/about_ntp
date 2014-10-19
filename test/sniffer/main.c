#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen

#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<time.h>
#include<stdbool.h>

#define TIME_SERVER_IP "91.189.94.4"
#define OWN_IP "192.168.0.2"

#define JAN_1970        0x83aa7e80      /* 2208988800 1970 - 1900 in seconds */

#define NTP_TO_UNIX(n,u) do {  u = n - JAN_1970; } while (0)


#define HTONL_FP(h, n)  do { (n)->l_ui = htonl((h)->l_ui); \
                                 (n)->l_uf = htonl((h)->l_uf); } while (0)

#define NTOHL_FP(n, h)  do { (h)->l_ui = ntohl((n)->l_ui); \
                                 (h)->l_uf = ntohl((n)->l_uf); } while (0)

#define HTONL_F(f, nts) do { (nts)->l_uf = htonl(f); \
                                    if ((f) & 0x80000000) \
                                            (nts)->l_i = -1; \
                                    else \
                                            (nts)->l_i = 0; \
                            } while (0)

#define l_ui    Ul_i.Xl_ui              /* unsigned integral part */
#define l_i     Ul_i.Xl_i               /* signed integral part */
#define l_uf    Ul_f.Xl_uf              /* unsigned fractional part */
#define l_f     Ul_f.Xl_f               /* signed fractional part */

typedef struct {
  union {
    uint32_t Xl_ui;
    int32_t Xl_i;
  } Ul_i;
  union {
    uint32_t Xl_uf;
    int32_t Xl_f;
  } Ul_f;
} l_fp;

struct pkt {
  uint8_t  li_vn_mode;     /* leap indicator, version and mode */
  uint8_t  stratum;        /* peer stratum */
  uint8_t  ppoll;          /* peer poll interval */
  int8_t  precision;      /* peer clock precision */
  uint32_t    rootdelay;      /* distance to primary clock */
  uint32_t    rootdispersion; /* clock dispersion */
  uint32_t refid;          /* reference clock ID */
  l_fp    ref;        /* time peer clock was last updated */
  l_fp    org;            /* originate time stamp */
  l_fp    rec;            /* receive time stamp */
  l_fp    xmt;            /* transmit time stamp */

#define LEN_PKT_NOMAC   12 * sizeof(uint32_t) /* min header length */
#define LEN_PKT_MAC     LEN_PKT_NOMAC +  sizeof(uint32_t)
#define MIN_MAC_LEN     3 * sizeof(uint32_t)     /* DES */
#define MAX_MAC_LEN     5 * sizeof(uint32_t)     /* MD5 */

  /*
   * The length of the packet less MAC must be a multiple of 64
   * with an RSA modulus and Diffie-Hellman prime of 64 octets
   * and maximum host name of 128 octets, the maximum autokey
   * command is 152 octets and maximum autokey response is 460
   * octets. A packet can contain no more than one command and one
   * response, so the maximum total extension field length is 672
   * octets. But, to handle humungus certificates, the bank must
   * be broke.
   */
#ifdef OPENSSL
  uint32_t exten[NTP_MAXEXTEN / 4]; /* max extension field */
#else /* OPENSSL */
  uint32_t exten[1];       /* misused */
#endif /* OPENSSL */
  uint8_t  mac[MAX_MAC_LEN]; /* mac */
};

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_udp_packet(unsigned char * , int );
void PrintData (unsigned char* , int);

FILE *logfile;
struct sockaddr_in source,dest;
int udp=0,others=0,total=0,i,j;

int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    logfile=fopen("log.txt","w");
    if(logfile==NULL)
    {
        printf("Unable to create log.txt file.");
    }
    printf("Starting...\n");

    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
        fflush(logfile);
    }
    close(sock_raw);
    return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 17: //UDP Protocol
            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol
            ++others;
            break;
    }
    printf("UDP : %d   Others : %d   Total : %d\r",
            udp , others , total);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile ,
            "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
            eth->h_dest[0] , eth->h_dest[1] ,
            eth->h_dest[2] , eth->h_dest[3] ,
            eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile ,
            "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
            eth->h_source[0] , eth->h_source[1] ,
            eth->h_source[2] , eth->h_source[3] ,
            eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",
            (unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    //print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    //fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    //fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    //fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    //fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    //fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    //fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    //fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_ntp_packet(unsigned char *ntp_payload, int Size)
{
    struct pkt *msg = (struct pkt*)(ntp_payload);

    fprintf(logfile , "\n");
    fprintf(logfile , "NTP Payload\n");
    fprintf(logfile , "   |-Li_Vm_Mode        : %Xh\n", msg->li_vn_mode);
    fprintf(logfile , "   |-Stratum           : %d\n", msg->stratum);
    fprintf(logfile , "   |-Ppoll             : %d\n", msg->ppoll);
    fprintf(logfile , "   |-Precision         : %d\n", msg->precision);
    fprintf(logfile , "   |-Root Delay        : %Xh\n", ntohl(msg->rootdelay));
    fprintf(logfile , "   |-Root Dispersion   : %d\n", ntohl(msg->rootdispersion));
    fprintf(logfile , "   |-Reference Id      : %d\n", msg->refid);

    struct pkt *prt = malloc(sizeof(struct pkt));

    NTOHL_FP(&msg->ref, &prt->ref);
    NTOHL_FP(&msg->org, &prt->org);
    NTOHL_FP(&msg->rec, &prt->rec);
    NTOHL_FP(&msg->xmt, &prt->xmt);

    fprintf(logfile , "   |-Reference Time I  : %u\n", prt->ref.Ul_i.Xl_ui);
    fprintf(logfile , "   |-Reference Time F  : %u\n", prt->ref.Ul_f.Xl_f);
    fprintf(logfile , "   |-Originate Time I  : %u\n", prt->org.Ul_i.Xl_ui);
    fprintf(logfile , "   |-Originate Time F  : %u\n", prt->org.Ul_f.Xl_f);
    fprintf(logfile , "   |-Receive  Time I   : %u\n", prt->rec.Ul_i.Xl_ui);
    fprintf(logfile , "   |-Receiver Time F   : %u\n", prt->rec.Ul_f.Xl_f);
    fprintf(logfile , "   |-Transmit Time I   : %u\n", prt->xmt.Ul_i.Xl_ui);
    fprintf(logfile , "   |-Transmit Time F   : %u\n", prt->xmt.Ul_f.Xl_f);

    fprintf(logfile , "\n");
    fprintf(logfile , "NTP Human Time\n");

    time_t seconds;
    char buffer[20];

    NTP_TO_UNIX(prt->ref.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    if (prt->ref.Ul_i.Xl_ui != 0)
        fprintf(logfile , "   |-Reference Time    : %s.%u\n", buffer, prt->ref.Ul_f.Xl_f);

    NTP_TO_UNIX(prt->org.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    if (prt->org.Ul_i.Xl_ui != 0)
        fprintf(logfile , "   |-Originate Time    : %s.%u\n", buffer, prt->org.Ul_f.Xl_f);

    NTP_TO_UNIX(prt->rec.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    if (prt->rec.Ul_i.Xl_ui != 0)
        fprintf(logfile , "   |-Receive Time      : %s.%u\n", buffer, prt->rec.Ul_f.Xl_f);

    NTP_TO_UNIX(prt->xmt.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    if (prt->xmt.Ul_i.Xl_ui != 0)
        fprintf(logfile , "   |-Transmit Time     : %s.%u\n", buffer, prt->xmt.Ul_f.Xl_f);
}

uint32_t char_to_uint32(char *network) {
    struct in_addr sock_network;
    memset(&sock_network, 0, sizeof(struct in_addr));

    inet_aton(network, &sock_network);
    return sock_network.s_addr;
}

bool is_not_eth0(unsigned char *Buffer, int Size)
{
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    uint32_t own_addr = char_to_uint32(OWN_IP);
    // Src ip is that of a given timeserver
    if (own_addr == source.sin_addr.s_addr ||
        own_addr == dest.sin_addr.s_addr) {
        return false;
    }
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    return true;
}

bool is_not_given_timeserver(unsigned char *Buffer, int Size)
{
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    uint32_t own_addr = char_to_uint32(TIME_SERVER_IP);
    // Src ip is that of a given timeserver
    if (own_addr == source.sin_addr.s_addr ||
        own_addr == dest.sin_addr.s_addr) {
        return false;
    }
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    return true;
}

void print_udp_packet(unsigned char *Buffer , int Size)
{
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);

    // Only NTP packets will be printed
    if ( !( ntohs(udph->dest) == 123 &&
           ntohs(udph->source) == 123 ))
        return;

    if (is_not_eth0(Buffer, Size))
        return;

    //if(is_not_given_timeserver(Buffer, Size))
    //    return;

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    //fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    //fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    //fprintf(logfile , "\n");
    //fprintf(logfile , "IP Header\n");
    //PrintData(Buffer+(sizeof (struct ethhdr)) , iphdrlen);
    //fprintf(logfile , "\n");

    //fprintf(logfile , "UDP Header\n");
    //PrintData(Buffer+iphdrlen+sizeof(struct ethhdr) , sizeof(struct udphdr));
    //fprintf(logfile , "\n");

    //fprintf(logfile , "Data Payload\n");
    //PrintData(Buffer + header_size , Size - header_size);

    print_ntp_packet(Buffer + header_size, Size - header_size);

    fprintf(logfile , "\n###########################################################");
    ++udp;
}

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(logfile , "   "); //extra spaces
            }

            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }

            fprintf(logfile ,  "\n" );
        }
    }
}
