//
// Created by Iscle on 31/01/2021.
//

#include "utils.h"
#include <sys/socket.h>
#include <iostream>
#include <unistd.h>
#include <netdb.h>

void utils::ByteArray::write_int(int data) {
    write_byte((data >> 24) & 0xFF);
    write_byte((data >> 16) & 0xFF);
    write_byte((data >> 8) & 0xFF);
    write_byte((data >> 0) & 0xFF);
}

void utils::ByteArray::write_byte(uint8_t data) {
    vec.push_back(data);
}

void utils::ByteArray::write(const std::string &data) {
    for (char i : data)
        vec.push_back(i);
}

void utils::ByteArray::write(const char *data, size_t length) {
    for (size_t i = 0; i < length; i++)
        vec.push_back(data[i]);
}

size_t utils::ByteArray::array(uint8_t **data) {
    *data = vec.data();
    return vec.size();
}

void utils::ByteArray::write_short(short data) {
    write_byte(data >> 8);
    write_byte(data >> 0);
}


utils::ConnectionHolder::ConnectionHolder(const std::string &addr, const std::string &port) {
    struct addrinfo hints = {0};
    struct addrinfo *addrs;
    struct addrinfo *i;
    int sockfd;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(addr.c_str(), port.c_str(), &hints, &addrs) < 0) {
        // TODO: Handle error
        std::cout << "Failed to get accesspoint addr info!" << std::endl;
    }

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

    if (sockfd == -1) {
        // TODO: Handle error
        std::cout << "Failed to connect to " << addr << ":" << port << std::endl;
        return;
    }

    this->sockfd = sockfd;
}

utils::ConnectionHolder utils::ConnectionHolder::create(const std::string &addr) {
    size_t colon = addr.find(':');
    std::string ap_addr = addr.substr(0, colon);
    std::string ap_port = addr.substr(colon + 1);

    std::cout << "Connecting to " << addr << std::endl;

    return {ap_addr, ap_port};
}

void utils::ConnectionHolder::write_byte(uint8_t data) const {
    if (::write(sockfd, &data, 1) != 1) {
        // TODO: Handle error
        std::cout << "Failed to write data into sockfd!" << std::endl;
    }
}

void utils::ConnectionHolder::write(const std::string &data) const {
    if (::write(sockfd, data.c_str(), data.size()) != data.size()) {
        // TODO: Handle error
        std::cout << "Failed to write data into sockfd!" << std::endl;
    }
}

void utils::ConnectionHolder::write_int(int data) const {
    write_byte((data >> 24) & 0xFF);
    write_byte((data >> 16) & 0xFF);
    write_byte((data >> 8) & 0xFF);
    write_byte((data >> 0) & 0xFF);
}

int utils::ConnectionHolder::read_int() const {
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

    if (ret != 4) {
        // TODO: Handle error
        std::cout << "read_int() failed!" << std::endl;
    }

    return data;
}

void utils::ConnectionHolder::read_fully(uint8_t *data, size_t len) const {
    int n = 0;

    while (n < len) {
        int count = ::read(this->sockfd, data + n, len - n);
        if (count < 0) {
            // TODO: Handle error
            std::cout << "read_fully() failed!" << std::endl;
            continue;
        }
        n += count;
    }
}

ssize_t utils::ConnectionHolder::write(const uint8_t *data, size_t size) const {
    return ::write(sockfd, data, size);
}

int utils::ConnectionHolder::read(uint8_t *data, size_t len) const {
    return ::read(sockfd, data, len);
}

void utils::ConnectionHolder::restore_timeout() {
    if (original_timeout_set &&
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &original_timeout, sizeof(original_timeout)) < 0)
        std::cout << "Failed to restore socket send timeout!" << std::endl;
}

void utils::ConnectionHolder::set_timeout(int timeout) {
    struct timeval new_timeout = {0};
    new_timeout.tv_sec = timeout;

    size_t original_timeout_size = sizeof(original_timeout);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &original_timeout, (socklen_t *) &original_timeout_size) >= 0)
        original_timeout_set = true;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &new_timeout, sizeof(new_timeout)) < 0)
        std::cout << "Failed to set socket send timeout!" << std::endl;
}

std::string utils::generate_device_id() {
    return "209031ee9cc724ce46a6c4bf9140c70c4a9202c8";
}