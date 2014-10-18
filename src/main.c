#include "globals.h"
#include "ntp_client.h"

void test_util()
{
    print_size_of_data_types();

    //struct timeval t;
    //gettimeofday(&t, NULL);
    //print_human_time(&t.tv_sec);

    uint32_t ntp_time = 3622594522;
    time_t unix_time = ntp_time_to_unix_time(ntp_time);
    print_human_time(&unix_time);
}

int main(int argc, char *argv[])
{
    test_util();

    //run_client(argc, argv);

    return 0;
}

