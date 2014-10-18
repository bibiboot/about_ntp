#include <sys/time.h>
#include <stdint.h>
#include <time.h>

#include "globals.h"

void print_size_of_data_types();

void print_human_time(time_t *unix_time);

time_t ntp_time_to_unix_time(uint32_t ntp_time);

uint32_t unix_time_to_ntp_time(time_t unix_time);
