//
// Created by Iscle on 06/02/2021.
//

#ifndef LIBRESPOT_CPP_HMAC_SHA_1_H
#define LIBRESPOT_CPP_HMAC_SHA_1_H

#include <openssl/hmac.h>

#include <vector>
#include <cstdint>
#include <string>

class HMAC_SHA1 {
public:
    HMAC_SHA1();

    ~HMAC_SHA1();

    int init(std::vector<uint8_t> &key);

    int update(std::string &message);

    int update(std::vector<uint8_t> &message);

    int update(uint8_t *data, size_t size);

    int final(std::vector<uint8_t> &data);

private:
    HMAC_CTX *hmac_ctx;
};


#endif //LIBRESPOT_CPP_HMAC_SHA_1_H
