//
// Created by Iscle on 03/02/2021.
//

#include <netdb.h>
#include <iostream>
#include <unistd.h>
#include <spdlog/spdlog.h>
#include "connection_holder.h"

Connection::Connection(const std::string &addr) {
    size_t colon = addr.find(':');
    std::string ap_addr = addr.substr(0, colon);
    std::string ap_port = addr.substr(colon + 1);
    init(ap_addr, ap_port);
}

Connection::Connection(const std::string &ap_addr, const std::string &ap_port) {
    init(ap_addr, ap_port);
}

Connection::~Connection() {
    close(sockfd);
}

void Connection::init(const std::string &ap_addr, const std::string &ap_port) {
    SPDLOG_INFO("Connecting to {}:{}", ap_addr, ap_port);

    struct addrinfo hints = {};
    struct addrinfo *addrs;
    struct addrinfo *i;
    int sockfd;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(ap_addr.c_str(), ap_port.c_str(), &hints, &addrs) < 0)
        throw std::runtime_error("Failed to get accesspoint addr info!");

    for (i = addrs; i != nullptr; i = i->ai_next) {
        sockfd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
        if (sockfd < 0)
            break;

        if (!::connect(sockfd, i->ai_addr, i->ai_addrlen))
            break;

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(addrs);

    if (sockfd == -1) throw std::runtime_error("Could not connect to accesspoint");

    this->sockfd = sockfd;
}

void Connection::write(uint8_t data) const {
    if (::write(sockfd, &data, 1) != 1)
        throw std::runtime_error("Failed to write data!");
}

void Connection::write(const std::string &data) const {
    if (::write(sockfd, data.c_str(), data.size()) != (ssize_t) data.size())
        throw std::runtime_error("Failed to write data!");
}

void Connection::write(const std::vector<uint8_t> &data) const {
    if (::write(sockfd, data.data(), data.size()) != (ssize_t) data.size())
        throw std::runtime_error("Failed to write data!");
}

void Connection::write(const uint8_t *data, size_t size) const {
    if (::write(sockfd, data, size) != size)
        throw std::runtime_error("Failed to write data!");
}

void Connection::write_int(int data) const {
    data = htonl(data);
    write(reinterpret_cast<const uint8_t *>(&data), sizeof(data));
}

int Connection::read_int() const {
    int ret;
    int data;

    ret = ::read(sockfd, &data, sizeof(data));
    if (ret != sizeof(data))
        throw std::runtime_error("Failed to read data!");

    return ntohl(data);
}

std::vector<uint8_t> Connection::read_fully(size_t size) const {
    std::vector<uint8_t> data(size);
    size_t n = 0;

    while (n < size) {
        ssize_t count = ::read(this->sockfd, &data[n], size - n);
        if (count < 0)
            throw std::runtime_error("Failed to read data!");
        n += count;
    }

    return data;
}

std::vector<uint8_t> Connection::read(size_t size) const {
    std::vector<uint8_t> data(size);
    ssize_t ret;
    ret = ::read(sockfd, &data[0], size);
    if (ret < 0) data.clear();
    else data.resize(ret);
    return data;
}

void Connection::restore_timeout() {
    if (original_timeout_set &&
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &original_timeout, sizeof(original_timeout)) < 0)
        SPDLOG_DEBUG("Failed to restore socket send timeout.");
}

void Connection::set_timeout(int timeout) {
    struct timeval new_timeout = {};
    new_timeout.tv_sec = timeout;

    size_t original_timeout_size = sizeof(original_timeout);
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &original_timeout, (socklen_t *) &original_timeout_size) >= 0)
        original_timeout_set = true;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &new_timeout, sizeof(new_timeout)) < 0)
        SPDLOG_DEBUG("Failed to set socket send timeout.");
}