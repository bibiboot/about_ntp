#pragma once

#include <stdio.h>
#include <stdlib.h>

#include "util.h"

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
