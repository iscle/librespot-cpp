//
// Created by Iscle on 31/01/2021.
//

#ifndef LIBRESPOT_C_CIPHER_PAIR_H
#define LIBRESPOT_C_CIPHER_PAIR_H


#include <cstddef>
#include <cstdint>
#include <atomic>
#include <shannon/Shannon.h>
#include "packet.h"
#include "../utils.h"

class CipherPair {
public:
    CipherPair(uint8_t *send_key, size_t send_key_size, uint8_t *recv_key, size_t recv_key_size);

    void send_encoded(std::unique_ptr<utils::ConnectionHolder> &conn, uint8_t cmd, std::vector<uint8_t> &payload);

    Packet receive_encoded(std::unique_ptr<utils::ConnectionHolder> &conn);

private:
    shn_ctx send_cipher_ctx;
    shn_ctx recv_cipher_ctx;
    std::atomic<int> send_nonce;
    std::atomic<int> recv_nonce;
};


#endif //LIBRESPOT_C_CIPHER_PAIR_H
