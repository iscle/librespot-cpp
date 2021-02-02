//
// Created by Iscle on 27/01/2021.
//

#ifndef LIBRESPOT_C_BASE62_H
#define LIBRESPOT_C_BASE62_H

#include <vector>
#include <cstdint>

class Base62 {
public:
    static std::vector<uint8_t> decode(const std::vector<uint8_t> &data, size_t target_size);

    static std::vector<uint8_t> encode(std::vector<uint8_t> &data, size_t target_size);

private:
    static std::vector<uint8_t> convert(const std::vector<uint8_t> &data, int from, int to, size_t target_size);

    static std::vector<uint8_t> translate_decode(const std::vector<uint8_t> &data);

    static void translate_encode(std::vector<uint8_t> &data, size_t data_size);

};

#endif //LIBRESPOT_C_BASE62_H
