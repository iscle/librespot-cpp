//
// Created by Iscle on 27/01/2021.
//

#ifndef LIBRESPOT_C_BASE62_H
#define LIBRESPOT_C_BASE62_H

#include <vector>
#include <cstdint>

std::vector<uint8_t> base62_decode(const std::vector<uint8_t> &data, size_t target_size);

std::vector<uint8_t> base62_encode(std::vector<uint8_t> &data, size_t target_size);

#endif //LIBRESPOT_C_BASE62_H
