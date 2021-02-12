//
// Created by Iscle on 12/02/2021.
//

#ifndef LIBRESPOT_CPP_BYTE_BUFFER_H
#define LIBRESPOT_CPP_BYTE_BUFFER_H

#include <cstdint>
#include <string>
#include <vector>

class ByteBuffer {
public:
    ByteBuffer(std::vector<uint8_t> &vector);

    ByteBuffer(std::string &string);

    uint8_t get();

    short get_short();

    int get_int();

    long get_long();

    std::vector<uint8_t> get(size_t size);

private:
    std::vector<uint8_t> vector;
    size_t pos;
};

#endif //LIBRESPOT_CPP_BYTE_BUFFER_H
