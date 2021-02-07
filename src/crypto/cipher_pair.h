//
// Created by Iscle on 31/01/2021.
//

#ifndef LIBRESPOT_C_CIPHER_PAIR_H
#define LIBRESPOT_C_CIPHER_PAIR_H

#include <cstdint>
#include <shannon/Shannon.h>
#include <mutex>
#include "packet.h"
#include "../utils.h"
#include "../connection_holder.h"

class CipherPair {
public:
    CipherPair(std::shared_ptr<Connection> connection, uint8_t *send_key, size_t send_key_size, uint8_t *recv_key,
               size_t recv_key_size);

    void send_encoded(uint8_t cmd, std::vector<uint8_t> &payload);

    Packet receive_encoded();

private:
    const std::shared_ptr<Connection> connection;
    std::mutex send_mutex;
    std::mutex recv_mutex;
    shn_ctx send_cipher_ctx;
    shn_ctx recv_cipher_ctx;
    unsigned int send_nonce;
    unsigned int recv_nonce;
};


#endif //LIBRESPOT_C_CIPHER_PAIR_H
