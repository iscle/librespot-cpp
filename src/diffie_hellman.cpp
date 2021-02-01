//
// Created by Iscle on 27/01/2021.
//

#include "diffie_hellman.h"
#include <cstdint>
#include <iostream>
#include <openssl/rand.h>

static constexpr uint8_t P_BYTES[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2,
        0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67,
        0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e,
        0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
        0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5,
        0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static constexpr uint8_t G_BYTES[] = {0x02};

DiffieHellman::DiffieHellman() {
    int ret;
    uint8_t key_data[95];

    RAND_bytes(key_data, sizeof(key_data));

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_public_key = BN_new();
    BIGNUM *bn_private_key = BN_bin2bn(key_data, sizeof(key_data), nullptr);
    BIGNUM *bn_p = BN_bin2bn(P_BYTES, sizeof(P_BYTES), nullptr);
    BIGNUM *bn_g = BN_bin2bn(G_BYTES, sizeof(G_BYTES), nullptr);
    if (ctx == nullptr || bn_public_key == nullptr || bn_private_key == nullptr || bn_p == nullptr || bn_g == nullptr) {
        // TODO: Handle error
        if (bn_g != nullptr) BN_free(bn_g);
        if (bn_p != nullptr) BN_free(bn_p);
        if (bn_private_key != nullptr) BN_free(bn_private_key);
        if (bn_public_key != nullptr) BN_free(bn_public_key);
        if (ctx != nullptr) BN_CTX_free(ctx);
    }

    ret = BN_mod_exp(bn_public_key, bn_g, bn_private_key, bn_p, ctx);
    BN_free(bn_p);
    BN_free(bn_g);
    BN_CTX_free(ctx);
    if (ret != 1) {
        // TODO: Handle error
        std::cout << "Error while calculating public key!" << std::endl;
        BN_free(bn_private_key);
        BN_free(bn_public_key);
    }

    auto *public_key = (uint8_t *) OPENSSL_malloc(BN_num_bytes(bn_public_key));
    if (public_key == nullptr) {
        // TODO: Handle error
        std::cout << "Could not allocate memory for public key!" << std::endl;
        BN_free(bn_private_key);
        BN_free(bn_public_key);
    }

    int public_key_length = BN_bn2bin(bn_public_key, public_key);
    BN_free(bn_public_key);
    if (public_key_length < 0) {
        // TODO: Handle error
        std::cout << "Failed to copy server secret!" << std::endl;
        OPENSSL_free(public_key);
        BN_free(bn_private_key);
    }

    this->bn_private_key = bn_private_key;
    this->public_key = public_key;
    this->public_key_length = public_key_length;
}

DiffieHellman::~DiffieHellman() {
    BN_free(bn_private_key);
    OPENSSL_free(public_key);
}

int DiffieHellman::compute_shared_key(const std::string &remote_key, uint8_t **shared_key) {
    int ret;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_p = BN_bin2bn(P_BYTES, sizeof(P_BYTES), nullptr);
    BIGNUM *bn_remote_key = BN_bin2bn((const unsigned char *) remote_key.c_str(), remote_key.size(), nullptr);
    BIGNUM *bn_shared_key = BN_new();

    ret = BN_mod_exp(bn_shared_key, bn_remote_key, bn_private_key, bn_p, ctx);
    BN_free(bn_remote_key);
    BN_free(bn_p);
    BN_CTX_free(ctx);
    if (ret != 1) {
        // TODO: Handle error
        BN_free(bn_shared_key);
    }

    *shared_key = (uint8_t *) OPENSSL_malloc(BN_num_bytes(bn_shared_key));
    if (*shared_key == nullptr) {
        // TODO: Handle error
        BN_free(bn_shared_key);
    }

    ret = BN_bn2bin(bn_shared_key, *shared_key);
    BN_free(bn_shared_key);
    if (ret < 0) {
        // TODO: Handle error
        OPENSSL_free(*shared_key);
        *shared_key = nullptr;
    }

    return ret;
}

uint8_t *DiffieHellman::get_public_key() {
    return public_key;
}

int DiffieHellman::get_public_key_length() const {
    return public_key_length;
}
