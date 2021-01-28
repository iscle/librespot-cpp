//
// Created by Iscle on 27/01/2021.
//

#ifndef LIBRESPOT_C_DIFFIE_HELLMAN_H
#define LIBRESPOT_C_DIFFIE_HELLMAN_H

#include <openssl/dh.h>

typedef struct {
    DH *dh;
    BIGNUM *public_key;
    BIGNUM *private_key;
} dh_t;

#endif //LIBRESPOT_C_DIFFIE_HELLMAN_H
