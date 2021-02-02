//
// Created by Iscle on 31/01/2021.
//

#ifndef LIBRESPOT_C_UTILS_H
#define LIBRESPOT_C_UTILS_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>

namespace utils {
    class ByteArray {
    private:
        std::vector<uint8_t> vec;
    public:
        void write_int(int data);

        void write_byte(uint8_t data);

        void write(const std::string &data);

        void write(const char *data, size_t length);

        std::vector<uint8_t> vector();

        void write_short(short data);

        void write(const std::vector<uint8_t> &data);
    };

    class ConnectionHolder {
    public:
        static std::unique_ptr<ConnectionHolder> create(const std::string &addr);

        void write_int(int data) const;

        ssize_t write(const uint8_t *data, size_t size) const;

        void write(const std::string &data) const;

        void write_byte(uint8_t data) const;

        int read_int() const;

        int read(uint8_t *data, size_t len) const;

        std::vector<uint8_t> read_fully(size_t len) const;

        void set_timeout(int timeout);

        void restore_timeout();

        ConnectionHolder(const std::string &addr, const std::string &port);

        void write(const std::vector<uint8_t> &data) const;

    private:
        int sockfd;
        bool original_timeout_set = false;
        struct timeval original_timeout;

    };

    std::string generate_device_id();
}

#endif //LIBRESPOT_C_UTILS_H
