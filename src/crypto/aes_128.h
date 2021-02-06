//
// Created by Iscle on 06/02/2021.
//

#ifndef LIBRESPOT_CPP_AES_128_H
#define LIBRESPOT_CPP_AES_128_H

#include <openssl/evp.h>
#include <vector>

class AES128 {
public:
    AES128();

    ~AES128();

    int init(std::vector<uint8_t> &encryption_key, std::vector<uint8_t> &iv);

    int update(std::vector<uint8_t> &data);

    int final(std::vector<uint8_t> &data);

private:
    EVP_CIPHER_CTX *aes_ctx;
    int outl;
};

#endif //LIBRESPOT_CPP_AES_128_H
