//
// Created by Iscle on 31/01/2021.
//

#ifndef LIBRESPOT_C_UTILS_H
#define LIBRESPOT_C_UTILS_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <rapidjson/document.h>

namespace utils {
    class ByteArray : public std::vector<uint8_t> {
    public:
        void write_int(int data);

        void write_byte(uint8_t data);

        void write(const std::string &data);

        void write(const char *data, size_t length);

        void write_short(short data);

        void write(const std::vector<uint8_t> &data);
    };

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

    std::string generate_device_id();

    rapidjson::Value json_string(std::string &str, rapidjson::Document::AllocatorType &allocator);

    int read_blob_int(ByteBuffer &buffer);
}

#endif //LIBRESPOT_C_UTILS_H
