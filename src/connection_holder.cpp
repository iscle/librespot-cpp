//
// Created by Iscle on 03/02/2021.
//

#include <netdb.h>
#include <iostream>
#include <unistd.h>
#include <spdlog/spdlog.h>
#include "connection_holder.h"

ConnectionHolder::ConnectionHolder(const std::string &addr) {
    size_t colon = addr.find(':');
    std::string ap_addr = addr.substr(0, colon);
    std::string ap_port = addr.substr(colon + 1);

    spdlog::info("Connecting to {}", addr);

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

    if (sockfd == -1) throw std::runtime_error("Failed to connect to " + addr);

    this->sockfd = sockfd;
}

void ConnectionHolder::write_byte(uint8_t data) const {
    if (::write(sockfd, &data, 1) != 1)
        throw std::runtime_error("Failed to write data!");
}

void ConnectionHolder::write(const std::string &data) const {
    if (::write(sockfd, data.c_str(), data.size()) != (ssize_t) data.size())
        throw std::runtime_error("Failed to write data!");
}

void ConnectionHolder::write(const std::vector<uint8_t> &data) const {
    if (::write(sockfd, data.data(), data.size()) != (ssize_t) data.size())
        throw std::runtime_error("Failed to write data!");
}

void ConnectionHolder::write(const uint8_t *data, size_t size) const {
    if (::write(sockfd, data, size) != size)
        throw std::runtime_error("Failed to write data!");
}

void ConnectionHolder::write_int(int data) const {
    write_byte((data >> 24) & 0xFF);
    write_byte((data >> 16) & 0xFF);
    write_byte((data >> 8) & 0xFF);
    write_byte((data >> 0) & 0xFF);
}

int ConnectionHolder::read_int() const {
    int ret;
    uint8_t tmp;
    int data = 0;

    ret = ::read(sockfd, &tmp, 1);
    data |= tmp << 24;
    ret += ::read(sockfd, &tmp, 1);
    data |= tmp << 16;
    ret += ::read(sockfd, &tmp, 1);
    data |= tmp << 8;
    ret += ::read(sockfd, &tmp, 1);
    data |= tmp << 0;

    if (ret != 4)
        throw std::runtime_error("Failed to read data!");

    return data;
}

std::vector<uint8_t> ConnectionHolder::read_fully(size_t len) const {
    std::vector<uint8_t> data(len);
    size_t n = 0;

    while (n < len) {
        ssize_t count = ::read(this->sockfd, &data[n], len - n);
        if (count < 0)
            throw std::runtime_error("Failed to read data!");
        n += count;
    }

    return data;
}

ssize_t ConnectionHolder::read(uint8_t *data, size_t len) const {
    return ::read(sockfd, data, len);
}

void ConnectionHolder::restore_timeout() {
    if (original_timeout_set &&
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &original_timeout, sizeof(original_timeout)) < 0)
        spdlog::debug("Failed to restore socket send timeout.");
}

void ConnectionHolder::set_timeout(int timeout) {
    struct timeval new_timeout = {};
    new_timeout.tv_sec = timeout;

    size_t original_timeout_size = sizeof(original_timeout);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &original_timeout, (socklen_t *) &original_timeout_size) >= 0)
        original_timeout_set = true;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &new_timeout, sizeof(new_timeout)) < 0)
        spdlog::debug("Failed to set socket send timeout.");
}