//
// Created by Iscle on 27/01/2021.
//

#ifndef LIBRESPOT_C_DIFFIE_HELLMAN_H
#define LIBRESPOT_C_DIFFIE_HELLMAN_H

#include <openssl/dh.h>

class DiffieHellman {
public:
    DiffieHellman();
    uint8_t *get_public_key();
    int get_public_key_length() const;

private:
    const BIGNUM *bn_private_key;
    BIGNUM *bn_public_key;
    uint8_t *public_key;
    int public_key_length;
};

#endif //LIBRESPOT_C_DIFFIE_HELLMAN_H
