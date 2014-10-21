/*
 * http://stackoverflow.com/questions/16063408/does-ntp-gettime-actually-return-nanosecond-precision
 *
 * ntp_gettime is inturn calling getnstimeofday.
 * Returns time in nano seconds.
 */
#include <stdio.h>
#include <sys/timex.h>
#include <sys/time.h>

 int main(int argc, char **argv)
 {
     struct timeval tv;
     gettimeofday(&tv, NULL);

     struct ntptimeval ntptv;
     ntp_gettime(&ntptv);

     printf("gettimeofday: tv_sec = %ld, tv_usec = %ld\n",
                tv.tv_sec, tv.tv_usec);
     printf("ntp_gettime:  tv_sec = %ld, tv_usec = %ld\n",
                ntptv.time.tv_sec, ntptv.time.tv_usec);
 }
