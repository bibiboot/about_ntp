#include "util.h"

void print_size_of_data_types()
{
    printf("\nSize of [time_t] %lu\n", sizeof(time_t));
    printf("Size of [int] %lu\n", sizeof(int));
    printf("Size of [unsigned long] %lu\n", sizeof(unsigned long));
    printf("Size of [unsigned long long] %lu\n\n", sizeof(unsigned long long));
}

void print_human_time(time_t *unix_time)
{
    char buffer[30];
    strftime(buffer, 30, "%m-%d-%Y %T", localtime(unix_time));
    printf("Unix time: %lu, Human time : %s\n", *unix_time, buffer);
}

time_t ntp_time_to_unix_time(uint32_t ntp_time)
{
    time_t unix_time = ntp_time - JAN_1970;
    return unix_time;
}

uint32_t unix_time_to_ntp_time(time_t unix_time)
{
    uint32_t ntp_time = unix_time + JAN_1970;
    return ntp_time;
}
