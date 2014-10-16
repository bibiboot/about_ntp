#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>

#define JAN_1970        0x83aa7e80      /* 2208988800 1970 - 1900 in seconds */


#define NTP_TO_UNIX(n,u) do {  u = n - JAN_1970; } while (0)


#define HTONL_FP(h, n)  do { (n)->l_ui = htonl((h)->l_ui); \
                                 (n)->l_uf = htonl((h)->l_uf); } while (0)

#define NTOHL_FP(n, h)  do { (h)->l_ui = ntohl((n)->l_ui); \
                                 (h)->l_uf = ntohl((n)->l_uf); } while (0)

#define SA      struct sockaddr
#define MAXLINE 16384
#define READMAX 16384       //must be less than MAXLINE or equal
#define NUM_BLK 20
#define MAXSUB  512
#define URL_LEN 256
#define MAXHSTNAM 512
#define MAXPAGE 1024
#define MAXPOST 1638

#define LISTENQ         1024

/*
 * NTP uses two fixed point formats.  The first (l_fp) is the "long"
 * format and is 64 bits long with the decimal between bits 31 and 32.
 * This is used for time stamps in the NTP packet header (in network
 * byte order) and for internal computations of offsets (in local host
 * byte order). We use the same structure for both signed and unsigned
 * values, which is a big hack but saves rewriting all the operators
 * twice. Just to confuse this, we also sometimes just carry the
 * fractional part in calculations, in both signed and unsigned forms.
 * Anyway, an l_fp looks like:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Integral Part                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Fractional Part                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * REF http://www.eecis.udel.edu/~mills/database/rfc/rfc2030.txt
 */


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


#define l_ui    Ul_i.Xl_ui              /* unsigned integral part */
#define l_i     Ul_i.Xl_i               /* signed integral part */
#define l_uf    Ul_f.Xl_uf              /* unsigned fractional part */
#define l_f     Ul_f.Xl_f               /* signed fractional part */

#define HTONL_F(f, nts) do { (nts)->l_uf = htonl(f); \
                                    if ((f) & 0x80000000) \
                                            (nts)->l_i = -1; \
                                    else \
                                            (nts)->l_i = 0; \
                            } while (0)

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

void send_ntp_packet(int sockfd, struct sockaddr *pcliaddr,
                     socklen_t servlen)
{
    struct pkt *msg = malloc(sizeof(struct pkt));

    msg->li_vn_mode = 227;
    msg->stratum = 0;
    msg->ppoll = 4;
    msg->precision = 0;
    msg->rootdelay = 0;
    msg->rootdispersion = 0;
    msg->ref.Ul_i.Xl_i = 0;
    msg->ref.Ul_f.Xl_f = 0;
    msg->org.Ul_i.Xl_i = 0;
    msg->org.Ul_f.Xl_f = 0;
    msg->rec.Ul_i.Xl_i = 0;
    msg->rec.Ul_f.Xl_f = 0;
    msg->xmt.Ul_i.Xl_i = 0;
    msg->xmt.Ul_f.Xl_f = 0;


    fprintf(stderr,"*************  INITIAL VALUES BEFORE SEND  *******************\n");

    fprintf(stderr,"li_vn_mode %Xh  size %lu\n",msg->li_vn_mode,sizeof(msg->li_vn_mode) );
    fprintf(stderr,"stratum %d size %lu\n",msg->stratum,sizeof(msg->stratum));
    fprintf(stderr,"ppoll %d size %lu\n",msg->ppoll,sizeof(msg->ppoll));
    fprintf(stderr,"precision %d  size %lu\n",msg->precision,sizeof(msg->precision));
    fprintf(stderr,"rootdelay %d size %lu\n",msg->rootdelay,sizeof(msg->rootdelay));
    fprintf(stderr,"rootdispersion %d %lu\n",msg->rootdispersion,sizeof(msg->rootdispersion));
    fprintf(stderr,"refid %d size %lu\n",msg->refid,sizeof(msg->refid));

    fprintf(stderr,"ref %u  %lu\n",msg->ref.Ul_i.Xl_ui,sizeof(msg->ref.Ul_i));
    fprintf(stderr,"ref %u  %lu\n",msg->ref.Ul_f.Xl_f,sizeof(msg->ref.Ul_f));

    fprintf(stderr,"org %u  %lu\n",msg->ref.Ul_i.Xl_ui,sizeof(msg->ref.Ul_i));
    fprintf(stderr,"org %u  %lu\n",msg->ref.Ul_f.Xl_f,sizeof(msg->ref.Ul_f));


    fprintf(stderr,"org %u  %lu\n",msg->org.Ul_i.Xl_ui,sizeof(msg->org.Ul_i));
    fprintf(stderr,"org %u  %lu\n",msg->org.Ul_f.Xl_f,sizeof(msg->org.Ul_f));

    fprintf(stderr,"rec %u  %lu\n",msg->rec.Ul_i.Xl_ui,sizeof(msg->rec.Ul_i));
    fprintf(stderr,"rec %u  %lu\n",msg->rec.Ul_f.Xl_f,sizeof(msg->rec.Ul_f));

    fprintf(stderr,"xmt %u  %lu\n",msg->xmt.Ul_i.Xl_ui,sizeof(msg->xmt.Ul_i));
    fprintf(stderr,"xmt %u  %lu\n",msg->xmt.Ul_f.Xl_f,sizeof(msg->xmt.Ul_f));

    fprintf(stderr,"*************  END INITIAL VALUES BEFORE SEND  ***************\n");

    int len=48;

    sendto(sockfd, (char *) msg, len, 0, pcliaddr, servlen);
    int n = recvfrom(sockfd, msg, len, 0, NULL, NULL);


    fprintf(stderr,"\n\n*************   2nd START  *******************\n");
    fprintf(stderr,"li_vn_mode %Xh  size %lu\n",msg->li_vn_mode,sizeof(msg->li_vn_mode) );
    fprintf(stderr,"stratum %d size %lu\n",msg->stratum,sizeof(msg->stratum));
    fprintf(stderr,"ppoll %d size %lu\n",msg->ppoll,sizeof(msg->ppoll));
    fprintf(stderr,"precision %d  size %lu\n",msg->precision,sizeof(msg->precision));
    fprintf(stderr,"rootdelay %Xh size %lu\n",ntohl(msg->rootdelay),sizeof(msg->rootdelay));
    fprintf(stderr,"rootdispersion %d %lu\n",ntohl(msg->rootdispersion),sizeof(msg->rootdispersion));
    fprintf(stderr,"refid %d size %lu\n",msg->refid,sizeof(msg->refid));

    struct pkt *prt = malloc(sizeof(struct pkt));

    NTOHL_FP(&msg->ref, &prt->ref);
    NTOHL_FP(&msg->org, &prt->org);
    NTOHL_FP(&msg->rec, &prt->rec);
    NTOHL_FP(&msg->xmt, &prt->xmt);

    fprintf(stderr,"ref %u  %lu\n",prt->ref.Ul_i.Xl_ui,sizeof(msg->ref.Ul_i));
    fprintf(stderr,"ref %u  %lu\n",prt->ref.Ul_f.Xl_f,sizeof(msg->ref.Ul_f));


    fprintf(stderr,"org %u  %lu\n",prt->org.Ul_i.Xl_ui,sizeof(prt->org.Ul_i));
    fprintf(stderr,"org %u  %lu\n",prt->org.Ul_f.Xl_f,sizeof(prt->org.Ul_f));

    fprintf(stderr,"rec %u  %lu\n",prt->rec.Ul_i.Xl_ui,sizeof(prt->rec.Ul_i));
    fprintf(stderr,"rec %u  %lu\n",prt->rec.Ul_f.Xl_f,sizeof(prt->rec.Ul_f));

    fprintf(stderr,"xmt %u  %lu\n",prt->xmt.Ul_i.Xl_ui,sizeof(prt->xmt.Ul_i));
    fprintf(stderr,"xmt %u  %lu\n",prt->xmt.Ul_f.Xl_f,sizeof(prt->xmt.Ul_f));

    time_t seconds;
    char buffer[20];

    NTP_TO_UNIX(prt->ref.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"\nref: %s.%u\n",buffer,prt->ref.Ul_f.Xl_f);


    NTP_TO_UNIX(prt->org.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"org: %s.%u\n",buffer,prt->org.Ul_f.Xl_f);

    NTP_TO_UNIX(prt->rec.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"rec: %s.%u\n",buffer,prt->rec.Ul_f.Xl_f);

    NTP_TO_UNIX(prt->xmt.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"xmt: %s.%u\n",buffer,prt->xmt.Ul_f.Xl_f);

    fprintf(stderr,"*************   2nd STOP  *******************\n");

    msg->li_vn_mode=227;
    msg->stratum=0;
    msg->ppoll=4;
    msg->precision=-6;
    msg->rootdelay=256;
    msg->rootdispersion=256;

    msg->ref.Ul_i.Xl_i= msg->xmt.Ul_i.Xl_i;
    msg->ref.Ul_f.Xl_f= msg->xmt.Ul_f.Xl_f;

    msg->org.Ul_i.Xl_i= msg->xmt.Ul_i.Xl_i;
    msg->org.Ul_f.Xl_f= msg->xmt.Ul_f.Xl_f;

    sendto(sockfd, (char *) msg, len, 0, pcliaddr, servlen);
    n = recvfrom(sockfd, msg, len, 0, NULL, NULL);

    fprintf(stderr,"\n\n*************   3nd START  *******************\n");
    fprintf(stderr,"li_vn_mode %Xh  size %lu\n",msg->li_vn_mode,sizeof(msg->li_vn_mode) );
    fprintf(stderr,"stratum %d size %lu\n",msg->stratum,sizeof(msg->stratum));
    fprintf(stderr,"ppoll %d size %lu\n",msg->ppoll,sizeof(msg->ppoll));
    fprintf(stderr,"precision %d  size %lu\n",msg->precision,sizeof(msg->precision));
    fprintf(stderr,"rootdelay %Xh size %lu\n",ntohl(msg->rootdelay),sizeof(msg->rootdelay));
    fprintf(stderr,"rootdispersion %d %lu\n",ntohl(msg->rootdispersion),sizeof(msg->rootdispersion));
    fprintf(stderr,"refid %d size %lu\n",msg->refid,sizeof(msg->refid));

    NTOHL_FP(&msg->ref, &prt->ref);
    NTOHL_FP(&msg->org, &prt->org);
    NTOHL_FP(&msg->rec, &prt->rec);
    NTOHL_FP(&msg->xmt, &prt->xmt);

    fprintf(stderr,"ref %u  %lu\n",prt->ref.Ul_i.Xl_ui,sizeof(msg->ref.Ul_i));
    fprintf(stderr,"ref %u  %lu\n",prt->ref.Ul_f.Xl_f,sizeof(msg->ref.Ul_f));
    fprintf(stderr,"org %u  %lu\n",prt->org.Ul_i.Xl_ui,sizeof(prt->org.Ul_i));
    fprintf(stderr,"org %u  %lu\n",prt->org.Ul_f.Xl_f,sizeof(prt->org.Ul_f));

    fprintf(stderr,"rec %u  %lu\n",prt->rec.Ul_i.Xl_ui,sizeof(prt->rec.Ul_i));
    fprintf(stderr,"rec %u  %lu\n",prt->rec.Ul_f.Xl_f,sizeof(prt->rec.Ul_f));

    fprintf(stderr,"xmt %u  %lu\n",prt->xmt.Ul_i.Xl_ui,sizeof(prt->xmt.Ul_i));
    fprintf(stderr,"xmt %u  %lu\n",prt->xmt.Ul_f.Xl_f,sizeof(prt->xmt.Ul_f));

    NTP_TO_UNIX(prt->ref.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"\nref: %s.%u\n",buffer,prt->ref.Ul_f.Xl_f);


    NTP_TO_UNIX(prt->org.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"org: %s.%u\n",buffer,prt->org.Ul_f.Xl_f);

    NTP_TO_UNIX(prt->rec.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"rec: %s.%u\n",buffer,prt->rec.Ul_f.Xl_f);

    NTP_TO_UNIX(prt->xmt.Ul_i.Xl_ui, seconds);
    strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
    fprintf(stderr,"xmt: %s.%u\n",buffer,prt->xmt.Ul_f.Xl_f);

    fprintf(stderr,"*************   3nd STOP  *******************\n");
    free(msg);
    free(prt);
}

int main(int argc, char *argv[])
{
    if(argc < 2) {
        fprintf(stderr,
                "./r timeserver1.upenn.edu\n"
                "or\n"
                "./r timex.usc.edu\n\n"
               );
        exit(1);
    }

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Socket not created");
        exit(1);
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(123);

    struct hostent *hptr;
    if ((hptr = gethostbyname(argv[1])) == NULL) {
        perror("Gethostbyname Failed");
        exit(1);
    }

    char **pptr;
    char str[50];
    if(hptr->h_addrtype == AF_INET
       && (pptr = hptr->h_addr_list) != NULL) {
        inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str));
    } else {
        perror("inet_ntop failed");
        exit(1);
    }

    inet_pton(AF_INET, str, &servaddr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        perror("Connect");
        exit(1);
    }

    send_ntp_packet(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    close(sockfd);

}
