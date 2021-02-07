//
// Created by Iscle on 06/02/2021.
//

#include <stdexcept>
#include "aes.h"

AES::AES(Type type) {
    aes_ctx = EVP_CIPHER_CTX_new();
    if (aes_ctx == nullptr) throw std::runtime_error("Failed to initialize context.");
    switch (type) {
        case AES_128_CTR:
            cipher = EVP_aes_128_ctr();
            break;
        case AES_192_ECB:
            cipher = EVP_aes_192_ecb();
            break;
        default:
            throw std::runtime_error("Unknown type!");
    }
    outl = 0;
}

int AES::init(std::vector<uint8_t> &encryption_key, std::vector<uint8_t> &iv) {
    // TODO: Check type
    return EVP_DecryptInit_ex(aes_ctx, cipher, nullptr, encryption_key.data(), iv.data());
}

int AES::init(std::vector<uint8_t> &encryption_key) {
    // TODO: Check type
    return EVP_DecryptInit_ex(aes_ctx, cipher, nullptr, encryption_key.data(), nullptr);
}

void AES::set_padding(int padding) {
    EVP_CIPHER_CTX_set_padding(aes_ctx, padding);
}

int AES::update(std::vector<uint8_t> &data) {
    return EVP_DecryptUpdate(aes_ctx, data.data(), &outl, data.data(), data.size());
}

int AES::update(std::string &data) {
    return EVP_DecryptUpdate(aes_ctx, (unsigned char *) data.data(), &outl,
                             reinterpret_cast<const unsigned char *>(data.data()), data.size());
}

int AES::final(std::vector<uint8_t> &data) {
    return EVP_DecryptFinal_ex(aes_ctx, data.data() + outl, &outl);
}

int AES::final(std::string &data) {
    return EVP_DecryptFinal_ex(aes_ctx, (unsigned char *) (data.data() + outl), &outl);
}

AES::~AES() {
    EVP_CIPHER_CTX_free(aes_ctx);
}
