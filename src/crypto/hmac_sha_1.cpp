//
// Created by Iscle on 06/02/2021.
//

#include <stdexcept>
#include "hmac_sha_1.h"

HMAC_SHA1::HMAC_SHA1() {
    hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == nullptr) throw std::runtime_error("Failed to initialize context.");
}

int HMAC_SHA1::init(std::vector<uint8_t> &key) {
    return HMAC_Init_ex(hmac_ctx, key.data(), key.size(), EVP_sha1(), nullptr);
}

int HMAC_SHA1::update(std::string &message) {
    return update((uint8_t *) message.data(), message.size());
}

int HMAC_SHA1::update(std::vector<uint8_t> &message) {
    return update(message.data(), message.size());
}

int HMAC_SHA1::update(uint8_t *data, size_t size) {
    return HMAC_Update(hmac_ctx, data, size);
}

int HMAC_SHA1::final(std::vector<uint8_t> &data) {
    data.resize(EVP_MD_size(EVP_sha1()));
    unsigned int data_length;
    return HMAC_Final(hmac_ctx, data.data(), &data_length);
}

HMAC_SHA1::~HMAC_SHA1() {
    HMAC_CTX_free(hmac_ctx);
}
