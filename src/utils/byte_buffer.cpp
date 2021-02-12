//
// Created by Iscle on 12/02/2021.
//

#include "byte_buffer.h"

ByteBuffer::ByteBuffer(std::vector<uint8_t> &vector) :
        vector(vector), pos(0) {

}

ByteBuffer::ByteBuffer(std::string &string) :
        vector(std::vector<uint8_t>(string.begin(), string.end())), pos(0) {

}

uint8_t ByteBuffer::get() {
    uint8_t data = *reinterpret_cast<uint8_t *>(&vector[pos]);
    pos += 1;
    return data;
}

short ByteBuffer::get_short() {
    short data = *reinterpret_cast<short *>(&vector[pos]);
    pos += 2;
    return data;
}

int ByteBuffer::get_int() {
    int data = *reinterpret_cast<int *>(&vector[pos]);
    pos += 4;
    return data;
}

long ByteBuffer::get_long() {
    long data = *reinterpret_cast<long *>(&vector[pos]);
    pos += 8;
    return data;
}

std::vector<uint8_t> ByteBuffer::get(size_t size) {
    std::vector<uint8_t> data(size);

    for (size_t i = 0; i < size; i++)
        data[i] = vector[pos++];

    return std::move(data);
}
