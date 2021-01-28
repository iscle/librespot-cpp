#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ap_resolver.h"
#include "data/base62.h"

int main() {
    //srand(time(NULL)); // To be called only one time

    //printf("%s\n", ap_resolver_get_dealer());
    //printf("%s\n", ap_resolver_get_dealer());

    //printf("%s\n", ap_resolver_get_spclient());
    //printf("%s\n", ap_resolver_get_spclient());

    //printf("%s\n", ap_resolver_get_accesspoint());
    //printf("%s\n", ap_resolver_get_accesspoint());

    int target_size = 16;
    uint8_t *decode = base62_decode("2fULWSOZgRtPoPZs0leeZV", sizeof("2fULWSOZgRtPoPZs0leeZV") - 1, target_size);
    for (int i = 0; i < target_size; i++) {
        printf("%02X", decode[i]);
    }
    printf("\n");
    int encode_size = 22;
    char *encode = base62_encode(decode, target_size, 22);
    for (int i = 0; i < encode_size; i++) {
        printf("%c", encode[i]);
    }
    printf("\n");

    free(decode);
    free(encode);

    ap_resolver_destroy();
    return 0;
}
