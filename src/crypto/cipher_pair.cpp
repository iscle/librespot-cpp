//
// Created by Iscle on 31/01/2021.
//

#include <cstring>
#include <iostream>
#include <memory>
#include "cipher_pair.h"
#include "../utils.h"

CipherPair::CipherPair(uint8_t *send_key, size_t send_key_size, uint8_t *recv_key, size_t recv_key_size) {
    shn_key(&send_cipher_ctx, send_key, send_key_size);
    send_nonce = 0;

    shn_key(&recv_cipher_ctx, recv_key, recv_key_size);
    recv_nonce = 0;
}

void CipherPair::send_encoded(std::unique_ptr<utils::ConnectionHolder> &conn, uint8_t cmd, uint8_t *payload, size_t payload_size) {
    // TODO: synchronize with send_cipher_ctx
    int nonce = send_nonce++;
    shn_nonce(&send_cipher_ctx, (unsigned char *) &nonce, sizeof(nonce));

    utils::ByteArray buffer;
    buffer.write_byte(cmd);
    buffer.write_short(payload_size);
    buffer.write((const char *) payload, payload_size);

    auto bytes = buffer.vector();
    shn_encrypt(&send_cipher_ctx, bytes.data(), bytes.size());

    auto mac = std::vector<uint8_t>(4);
    shn_finish(&send_cipher_ctx, mac.data(), mac.size());

    conn->write(bytes);
    conn->write(mac);
}

Packet CipherPair::receive_encoded(std::unique_ptr<utils::ConnectionHolder> &conn) {
    // TODO: synchronize with send_cipher_ctx
    int nonce = recv_nonce++;
    shn_nonce(&recv_cipher_ctx, (unsigned char *) &nonce, sizeof(nonce));

    auto header_bytes = conn->read_fully(3);
    shn_decrypt(&recv_cipher_ctx, header_bytes.data(), header_bytes.size());

    uint8_t cmd = header_bytes[0];
    auto payload_size = (short) ((header_bytes[1] << 8) | (header_bytes[2] << 0));
    auto payload = conn->read_fully(payload_size);
    shn_decrypt(&recv_cipher_ctx, payload.data(), payload.size());

    auto mac = conn->read_fully(4);

    std::vector<uint8_t> expected_mac(4);
    shn_finish(&recv_cipher_ctx, expected_mac.data(), expected_mac.size());
    if (mac != expected_mac) {
        // TODO: Handle error!
        std::cout << "MACs don't match!" << std::endl;
    }

    return {cmd, payload};
}
