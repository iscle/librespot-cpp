//
// Created by Iscle on 31/01/2021.
//

#include <netdb.h>
#include "cipher_pair.h"
#include "../utils/byte_array.h"

CipherPair::CipherPair(Connection &connection, uint8_t *send_key, size_t send_key_size,
                       uint8_t *recv_key, size_t recv_key_size) :
        connection(connection), send_cipher_ctx({}), send_nonce(0), recv_cipher_ctx({}), recv_nonce(0) {
    shn_key(&send_cipher_ctx, send_key, send_key_size);
    shn_key(&recv_cipher_ctx, recv_key, recv_key_size);
}

void CipherPair::send_encoded(uint8_t cmd, std::vector<uint8_t> &payload) {
    std::lock_guard<std::mutex> lock(send_mutex);
    unsigned int nonce = htonl(send_nonce++);
    shn_nonce(&send_cipher_ctx, (unsigned char *) &nonce, sizeof(nonce));

    ByteArray buffer;
    buffer.write(cmd);
    buffer.write_short(htons(payload.size()));
    buffer.write(payload);

    shn_encrypt(&send_cipher_ctx, buffer.data(), buffer.size());

    auto mac = std::vector<uint8_t>(4);
    shn_finish(&send_cipher_ctx, mac.data(), mac.size());

    connection.write(buffer);
    connection.write(mac);
}

Packet CipherPair::receive_encoded() {
    std::lock_guard<std::mutex> lock(recv_mutex);
    unsigned int nonce = htonl(recv_nonce++);
    shn_nonce(&recv_cipher_ctx, (unsigned char *) &nonce, sizeof(nonce));

    auto header_bytes = connection.read_fully(3);
    shn_decrypt(&recv_cipher_ctx, header_bytes.data(), header_bytes.size());

    uint8_t cmd = header_bytes[0];
    auto payload_size = ((unsigned short) header_bytes[1] << 8) | ((unsigned short) header_bytes[2] << 0);
    auto payload = connection.read_fully(payload_size);
    shn_decrypt(&recv_cipher_ctx, payload.data(), payload.size());

    auto mac = connection.read_fully(4);
    std::vector<uint8_t> expected_mac(4);
    shn_finish(&recv_cipher_ctx, expected_mac.data(), expected_mac.size());
    if (mac != expected_mac) throw std::runtime_error("MACs don't match!");

    return {cmd, payload};
}
