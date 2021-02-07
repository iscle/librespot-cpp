//
// Created by Iscle on 06/02/2021.
//

#ifndef LIBRESPOT_CPP_SHA_1_H
#define LIBRESPOT_CPP_SHA_1_H


#include <vector>
#include <cstdint>
#include <string>
#include <openssl/sha.h>

class SHA1 {
public:
    SHA1();

    int init();

    int update(std::vector<uint8_t> &data);

    int update(std::string &data);

    int final(std::vector<uint8_t> &data);

private:
    SHA_CTX sha_ctx;
};


#endif //LIBRESPOT_CPP_SHA_1_H
