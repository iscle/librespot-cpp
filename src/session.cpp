//
// Created by Iscle on 26/01/2021.
//

#include "session.h"
#include "version.h"
#include "ap_resolver.h"
#include "diffie_hellman.h"
#include <proto/keyexchange.pb.h>
#include <vector>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <netinet/tcp.h>

static const uint8_t SERVER_KEY[] = {
        0xac, 0xe0, 0x46, 0x0b, 0xff, 0xc2, 0x30, 0xaf, 0xf4, 0x6b, 0xfe, 0xc3, 0xbf, 0xbf, 0x86, 0x3d, 0xa1, 0x91,
        0xc6, 0xcc, 0x33, 0x6c, 0x93, 0xa1, 0x4f, 0xb3, 0xb0, 0x16, 0x12, 0xac, 0xac, 0x6a, 0xf1, 0x80, 0xe7, 0xf6,
        0x14, 0xd9, 0x42, 0x9d, 0xbe, 0x2e, 0x34, 0x66, 0x43, 0xe3, 0x62, 0xd2, 0x32, 0x7a, 0x1a, 0x0d, 0x92, 0x3b,
        0xae, 0xdd, 0x14, 0x02, 0xb1, 0x81, 0x55, 0x05, 0x61, 0x04, 0xd5, 0x2c, 0x96, 0xa4, 0x4c, 0x1e, 0xcc, 0x02,
        0x4a, 0xd4, 0xb2, 0x0c, 0x00, 0x1f, 0x17, 0xed, 0xc2, 0x2f, 0xc4, 0x35, 0x21, 0xc8, 0xf0, 0xcb, 0xae, 0xd2,
        0xad, 0xd7, 0x2b, 0x0f, 0x9d, 0xb3, 0xc5, 0x32, 0x1a, 0x2a, 0xfe, 0x59, 0xf3, 0x5a, 0x0d, 0xac, 0x68, 0xf1,
        0xfa, 0x62, 0x1e, 0xfb, 0x2c, 0x8d, 0x0c, 0xb7, 0x39, 0x2d, 0x92, 0x47, 0xe3, 0xd7, 0x35, 0x1a, 0x6d, 0xbd,
        0x24, 0xc2, 0xae, 0x25, 0x5b, 0x88, 0xff, 0xab, 0x73, 0x29, 0x8a, 0x0b, 0xcc, 0xcd, 0x0c, 0x58, 0x67, 0x31,
        0x89, 0xe8, 0xbd, 0x34, 0x80, 0x78, 0x4a, 0x5f, 0xc9, 0x6b, 0x89, 0x9d, 0x95, 0x6b, 0xfc, 0x86, 0xd7, 0x4f,
        0x33, 0xa6, 0x78, 0x17, 0x96, 0xc9, 0xc3, 0x2d, 0x0d, 0x32, 0xa5, 0xab, 0xcd, 0x05, 0x27, 0xe2, 0xf7, 0x10,
        0xa3, 0x96, 0x13, 0xc4, 0x2f, 0x99, 0xc0, 0x27, 0xbf, 0xed, 0x04, 0x9c, 0x3c, 0x27, 0x58, 0x04, 0xb6, 0xb2,
        0x19, 0xf9, 0xc1, 0x2f, 0x02, 0xe9, 0x48, 0x63, 0xec, 0xa1, 0xb6, 0x42, 0xa0, 0x9d, 0x48, 0x25, 0xf8, 0xb3,
        0x9d, 0xd0, 0xe8, 0x6a, 0xf9, 0x48, 0x4d, 0xa1, 0xc2, 0xba, 0x86, 0x30, 0x42, 0xea, 0x9d, 0xb3, 0x08, 0x6c,
        0x19, 0x0e, 0x48, 0xb3, 0x9d, 0x66, 0xeb, 0x00, 0x06, 0xa2, 0x5a, 0xee, 0xa1, 0x1b, 0x13, 0x87, 0x3c, 0xd7,
        0x19, 0xe6, 0x55, 0xbd
};

Session::Session(const std::string& addr) : conn(Session::ConnectionHolder::create(addr)) {
    //this->inner = nullptr;
    //this->keys = nullptr;
    //this->client = nullptr;
}

void Session::connect() {
    std::vector<uint8_t> acc;
    spotify::ClientHello client_hello;
    spotify::BuildInfo standard_build_info = Version::standard_build_info();
    uint8_t nonce[16];
    uint8_t padding = 0x1E;
    DiffieHellman dh;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        // TODO: Handle error
    }

    client_hello.set_allocated_build_info(&standard_build_info);
    client_hello.add_cryptosuites_supported(spotify::CRYPTO_SUITE_SHANNON);
    client_hello.mutable_login_crypto_hello()->mutable_diffie_hellman()->set_gc(dh.get_server_secret(), dh.get_server_secret_length());
    client_hello.mutable_login_crypto_hello()->mutable_diffie_hellman()->set_server_keys_known(1);
    client_hello.set_client_nonce(nonce, 16);
    client_hello.set_padding(&padding, 1);

    int length = 1 + 1 + 4 + (int) client_hello.ByteSizeLong();
    conn.write_byte(0);
    conn.write_byte(4);
    conn.write_int(length);
    conn.write(client_hello.SerializeAsString());
    //conn.flush();

    length = conn.read_int();
    auto *buffer = new uint8_t[length];
    conn.read_fully(buffer, length);

    spotify::APResponseMessage ap_response_message;
    ap_response_message.ParseFromArray(buffer, length);
    const std::string gs = ap_response_message.challenge().login_crypto_challenge().diffie_hellman().gs();

}

Session Session::create() {
    return {ap_resolver_get_accesspoint()};
}

Session::ConnectionHolder::ConnectionHolder(const std::string &addr, const std::string &port) {
    struct addrinfo hints = {0};
    struct addrinfo *addrs;
    struct addrinfo *i;
    int sockfd;
    std::string tmp_addr = "gew1-accesspoint-e-0fk9.ap.spotify.com";
    std::string tmp_port = "443";

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(tmp_addr.c_str(), tmp_port.c_str(), &hints, &addrs) < 0) {
        // TODO: Handle error
        std::cout << "Failed to get accesspoint addr info!" << std::endl;
    }

    for (i = addrs; i != nullptr; i = i->ai_next) {
        sockfd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
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
    }

    this->sockfd = sockfd;
}

Session::ConnectionHolder Session::ConnectionHolder::create(const std::string &addr) {
    size_t colon = addr.find(':');
    std::string ap_addr = addr.substr(0, colon);
    std::string ap_port = addr.substr(colon + 1);

    std::cout << "Connecting to " << addr << std::endl;

    return {ap_addr, ap_port};
}

void Session::ConnectionHolder::write_byte(uint8_t data) const {
    if (::write(sockfd, &data, 1) != 1) {
        // TODO: Handle error
        std::cout << "Failed to write data into sockfd!" << std::endl;
    }
}

void Session::ConnectionHolder::write(const std::string &data) const {
    if (::write(sockfd, data.c_str(), data.size()) != data.size()) {
        // TODO: Handle error
        std::cout << "Failed to write data into sockfd!" << std::endl;
    }
}

void Session::ConnectionHolder::write_int(int data) const {
    write_byte((data >> 24) & 0xFF);
    write_byte((data >> 16) & 0xFF);
    write_byte((data >> 8) & 0xFF);
    write_byte((data >> 0) & 0xFF);
}

int Session::ConnectionHolder::read_int() const {
    int ret;
    uint8_t tmp;
    int data = 0;

    ret = read(sockfd, &tmp, 1);
    data |= tmp << 24;
    ret += read(sockfd, &tmp, 1);
    data |= tmp << 16;
    ret += read(sockfd, &tmp, 1);
    data |= tmp << 8;
    ret += read(sockfd, &tmp, 1);
    data |= tmp << 0;

    if (ret != 4) {
        // TODO: Handle error
    }

    return data;
}

void Session::ConnectionHolder::read_fully(uint8_t *data, size_t len) {
    int n = 0;

    while (n < len) {
        int count = read(this->sockfd, data + n, len - n);
        if (count < 0) {
            // TODO: Handle error
        }
        n += count;
    }
}

void Session::ConnectionHolder::write(const uint8_t *data, size_t size) const {
    ::write(sockfd, data, size);
}
