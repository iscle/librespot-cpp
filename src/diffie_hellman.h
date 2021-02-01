//
// Created by Iscle on 27/01/2021.
//

#ifndef LIBRESPOT_C_DIFFIE_HELLMAN_H
#define LIBRESPOT_C_DIFFIE_HELLMAN_H

#include <openssl/bn.h>
#include <string>

class DiffieHellman {
public:
    DiffieHellman();
    ~DiffieHellman();

    uint8_t *get_public_key();
    int get_public_key_length() const;
    int compute_shared_key(const std::string& remote_key, uint8_t **shared_key);

private:
    BIGNUM *bn_private_key;
    uint8_t *public_key;
    int public_key_length;
};

#endif //LIBRESPOT_C_DIFFIE_HELLMAN_H
