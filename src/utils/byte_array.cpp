//
// Created by Iscle on 12/02/2021.
//

#include "byte_array.h"

void ByteArray::write_int(int data) {
    write_byte((data >> 24) & 0xFF);
    write_byte((data >> 16) & 0xFF);
    write_byte((data >> 8) & 0xFF);
    write_byte((data >> 0) & 0xFF);
}

void ByteArray::write_byte(uint8_t data) {
    push_back(data);
}

void ByteArray::write(const std::string &data) {
    for (char i : data)
        push_back(i);
}

void ByteArray::write(const std::vector<uint8_t> &data) {
    for (uint8_t i : data)
        push_back(i);
}

void ByteArray::write(const char *data, size_t length) {
    for (size_t i = 0; i < length; i++)
        push_back(data[i]);
}

void ByteArray::write_short(short data) {
    write_byte(data >> 8);
    write_byte(data >> 0);
}
