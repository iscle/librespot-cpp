//
// Created by Iscle on 02/02/2021.
//

#ifndef LIBRESPOT_CPP_PBKDF_2_H
#define LIBRESPOT_CPP_PBKDF_2_H

#include <cstdint>
#include <vector>
#include <string>

class PBKDF2 {
public:
    static int
    hmac_sha1(std::vector<uint8_t> &password, std::string &salt, int iterations, std::vector<uint8_t> &key);
};


#endif //LIBRESPOT_CPP_PBKDF_2_H
