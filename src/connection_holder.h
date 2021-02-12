//
// Created by Iscle on 03/02/2021.
//

#ifndef LIBRESPOT_CPP_CONNECTION_HOLDER_H
#define LIBRESPOT_CPP_CONNECTION_HOLDER_H


#include <memory>
#include <vector>

class Connection {
public:
    explicit Connection(const std::string &addr);

    Connection(const std::string &ap_addr, const std::string &ap_port);

    ~Connection();

    void write_int(int data) const;

    void write(const uint8_t *data, size_t size) const;

    void write(const std::string &data) const;

    void write(uint8_t data) const;

    int read_int() const;

    std::vector<uint8_t> read(size_t size) const;

    std::vector<uint8_t> read_fully(size_t size) const;

    void set_timeout(int timeout);

    void restore_timeout();

    void write(const std::vector<uint8_t> &data) const;

private:
    int sockfd;
    bool original_timeout_set = false;
    struct timeval original_timeout;

    void init(const std::string &ap_addr, const std::string &ap_port);
};


#endif //LIBRESPOT_CPP_CONNECTION_HOLDER_H
