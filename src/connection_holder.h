//
// Created by Iscle on 03/02/2021.
//

#ifndef LIBRESPOT_CPP_CONNECTION_HOLDER_H
#define LIBRESPOT_CPP_CONNECTION_HOLDER_H


#include <memory>
#include <vector>

class ConnectionHolder {
public:
    void write_int(int data) const;

    void write(const uint8_t *data, size_t size) const;

    void write(const std::string &data) const;

    void write_byte(uint8_t data) const;

    int read_int() const;

    ssize_t read(uint8_t *data, size_t len) const;

    std::vector<uint8_t> read_fully(size_t len) const;

    void set_timeout(int timeout);

    void restore_timeout();

    ConnectionHolder(const std::string &addr);

    void write(const std::vector<uint8_t> &data) const;

private:
    int sockfd;
    bool original_timeout_set = false;
    struct timeval original_timeout;

};


#endif //LIBRESPOT_CPP_CONNECTION_HOLDER_H
