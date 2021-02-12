//
// Created by Iscle on 12/02/2021.
//

#ifndef LIBRESPOT_CPP_BYTE_ARRAY_H
#define LIBRESPOT_CPP_BYTE_ARRAY_H

#include <cstdint>
#include <string>
#include <vector>

class ByteArray : public std::vector<uint8_t> {
public:
    void write_int(int data);

    void write_byte(uint8_t data);

    void write(const std::string &data);

    void write(const char *data, size_t length);

    void write_short(short data);

    void write(const std::vector<uint8_t> &data);
};



#endif //LIBRESPOT_CPP_BYTE_ARRAY_H
