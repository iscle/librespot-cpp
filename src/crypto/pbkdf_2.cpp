//
// Created by Iscle on 02/02/2021.
//

#include <openssl/evp.h>
#include "pbkdf_2.h"

int PBKDF2::hmac_sha1(std::vector<uint8_t> &password, std::string &salt, int iterations, std::vector<uint8_t> &key) {
    return PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char *>(password.data()), password.size(),
                                  reinterpret_cast<const unsigned char *>(salt.data()), salt.size(), iterations,
                                  key.size(), key.data());
}