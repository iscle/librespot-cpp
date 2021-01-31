//
// Created by Iscle on 27/01/2021.
//

#include "diffie_hellman.h"
#include <cstdint>
#include <iostream>
#include <openssl/rand.h>

static const uint8_t P_BYTES[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2,
        0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67,
        0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e,
        0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
        0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5,
        0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const uint8_t G_BYTES[] = {0x02};

DiffieHellman::DiffieHellman() {
    BN_CTX *ctx;
    uint8_t key_data[95];

    ctx = BN_CTX_new();
    bn_public_key = BN_new();
    if (ctx == nullptr || bn_public_key == nullptr) {
        // TODO: Handle error
    }

    if (RAND_bytes(key_data, sizeof(key_data)) != 1) {
        // TODO: Handle error
        std::cout << "Failed to generate random key data!" << std::endl;
    }

    bn_private_key = BN_bin2bn(key_data, sizeof(key_data), nullptr);
    const BIGNUM *bn_p = BN_bin2bn(P_BYTES, sizeof(P_BYTES), nullptr);
    const BIGNUM *bn_g = BN_bin2bn(G_BYTES, sizeof(G_BYTES), nullptr);
    if (bn_private_key == nullptr || bn_p == nullptr || bn_g == nullptr) {
        // TODO: Handle error
        std::cout << "Failed to parse private key and/or P and/or G!" << std::endl;
    }

    if (BN_mod_exp(bn_public_key, bn_g, bn_private_key, bn_p, ctx) != 1) {
        // TODO: Handle error
        std::cout << "Error while calculating public key!" << std::endl;
    }

    public_key = (uint8_t *) OPENSSL_malloc(BN_num_bytes(bn_public_key));
    if (public_key == nullptr) {
        // TODO: Handle error
        std::cout << "Could not allocate memory for public key!" << std::endl;
    }
    public_key_length = BN_bn2bin(bn_public_key, public_key);
    if (public_key_length < 0) {
        // TODO: Handle error
        std::cout << "Failed to copy server secret!" << std::endl;
    }
}

uint8_t *DiffieHellman::get_public_key() {
    return public_key;
}

int DiffieHellman::get_public_key_length() const {
    return public_key_length;
}