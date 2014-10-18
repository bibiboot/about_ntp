#include "ntp_client.h"

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

int run_client(int argc, char *argv[])
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
