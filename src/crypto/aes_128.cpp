//
// Created by Iscle on 06/02/2021.
//

#include <stdexcept>
#include "aes_128.h"

AES128::AES128() {
    aes_ctx = EVP_CIPHER_CTX_new();
    if (aes_ctx == nullptr) throw std::runtime_error("Failed to initialize context.");
    outl = 0;
}

int AES128::init(std::vector<uint8_t> &encryption_key, std::vector<uint8_t> &iv) {
    return EVP_DecryptInit_ex(aes_ctx, EVP_aes_128_ctr(), nullptr, encryption_key.data(), iv.data());
}

int AES128::update(std::vector<uint8_t> &data) {
    return EVP_DecryptUpdate(aes_ctx, data.data(), &outl, data.data(), data.size());
}

int AES128::final(std::vector<uint8_t> &data) {
    return EVP_DecryptFinal_ex(aes_ctx, data.data() + outl, &outl);
}

AES128::~AES128() {
    EVP_CIPHER_CTX_free(aes_ctx);
}
