#include <iostream>
#include "data/base62.h"
#include "ap_resolver.h"

int main() {
    //srand(time(NULL)); // To be called only one time

    std::cout << ap_resolver_get_dealer() << std::endl;
    std::cout << ap_resolver_get_dealer() << std::endl;

    std::cout << ap_resolver_get_spclient() << std::endl;
    std::cout << ap_resolver_get_spclient() << std::endl;

    std::cout << ap_resolver_get_accesspoint() << std::endl;
    std::cout << ap_resolver_get_accesspoint() << std::endl;

    //printf("%s\n", ap_resolver_get_dealer());
    //printf("%s\n", ap_resolver_get_dealer());

    //printf("%s\n", ap_resolver_get_spclient());
    //printf("%s\n", ap_resolver_get_spclient());

    //printf("%s\n", ap_resolver_get_accesspoint());
    //printf("%s\n", ap_resolver_get_accesspoint());

    std::string encoded_str = "2fULWSOZgRtPoPZs0leeZV";
    std::vector<uint8_t> encoded(encoded_str.begin(), encoded_str.end());
    std::vector<uint8_t> decode = base62_decode(encoded, 16);
    for (uint8_t i : decode)
        std::cout << std::hex << int(i);
    std::cout << std::endl;

    std::vector<uint8_t> encode = base62_encode(decode, 22);
    for (uint8_t i : encode)
        std::cout << char(i);
    std::cout << std::endl;

    //ap_resolver_destroy();
    return 0;
}
