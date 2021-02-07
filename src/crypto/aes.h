//
// Created by Iscle on 06/02/2021.
//

#ifndef LIBRESPOT_CPP_AES_H
#define LIBRESPOT_CPP_AES_H

#include <openssl/evp.h>
#include <vector>
#include <string>

class AES {
public:
    enum Type {
        AES_128_CTR,
        AES_192_ECB,
    };

    AES(Type type);

    ~AES();

    int init(std::vector<uint8_t> &encryption_key, std::vector<uint8_t> &iv);

    int init(std::vector<uint8_t> &encryption_key);

    void set_padding(int padding);

    int update(std::vector<uint8_t> &data);

    int update(std::string &data);

    int final(std::vector<uint8_t> &data);

    int final(std::string &data);

private:
    EVP_CIPHER_CTX *aes_ctx;
    const evp_cipher_st *cipher;
    int outl;
};

#endif //LIBRESPOT_CPP_AES_H
