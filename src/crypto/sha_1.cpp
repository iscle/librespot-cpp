//
// Created by Iscle on 06/02/2021.
//

#include "sha_1.h"

SHA1::SHA1() {
    sha_ctx = {};
}

int SHA1::init() {
    return SHA1_Init(&sha_ctx);
}

int SHA1::update(std::vector<uint8_t> &data) {
    return SHA1_Update(&sha_ctx, data.data(), data.size());
}

int SHA1::update(std::string &data) {
    return SHA1_Update(&sha_ctx, data.data(), data.size());
}

int SHA1::final(std::vector<uint8_t> &data) {
    data.resize(SHA_DIGEST_LENGTH);
    return SHA1_Final(data.data(), &sha_ctx);
}
