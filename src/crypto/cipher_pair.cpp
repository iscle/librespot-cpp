//
// Created by Iscle on 31/01/2021.
//

#include <cstring>
#include <iostream>
#include "cipher_pair.h"
#include "../utils.h"

CipherPair::CipherPair(uint8_t *send_key, size_t send_key_size, uint8_t *recv_key, size_t recv_key_size) {
    shn_key(&send_cipher_ctx, send_key, send_key_size);
    send_nonce = 0;

    shn_key(&recv_cipher_ctx, recv_key, recv_key_size);
    recv_nonce = 0;
}

void CipherPair::send_encoded(utils::ConnectionHolder &conn, uint8_t cmd, uint8_t *payload, size_t payload_size) {
    // TODO: synchronize with send_cipher_ctx
    int nonce = send_nonce++;
    shn_nonce(&send_cipher_ctx, (unsigned char *) &nonce, sizeof(nonce));

    utils::ByteArray buffer;
    buffer.write_byte(cmd);
    buffer.write_short(payload_size);
    buffer.write((const char *) payload, payload_size);

    uint8_t *bytes;
    size_t bytes_size = buffer.array(&bytes);
    shn_encrypt(&send_cipher_ctx, bytes, bytes_size);

    uint8_t mac[4];
    shn_finish(&send_cipher_ctx, mac, sizeof(mac));

    conn.write(bytes, bytes_size);
    conn.write(mac, sizeof(mac));
}

Packet CipherPair::receive_encoded(utils::ConnectionHolder &conn) {
    // TODO: synchronize with send_cipher_ctx
    int nonce = recv_nonce++;
    shn_nonce(&recv_cipher_ctx, (unsigned char *) &nonce, sizeof(nonce));

    uint8_t header_bytes[3];
    conn.read_fully(header_bytes, sizeof(header_bytes));
    shn_decrypt(&recv_cipher_ctx, header_bytes, sizeof(header_bytes));

    uint8_t cmd = header_bytes[0];
    auto payload_size = (short) ((header_bytes[1] << 8) | (header_bytes[2] << 0));
    auto *payload_bytes = new uint8_t[payload_size];
    conn.read_fully(payload_bytes, payload_size);
    shn_decrypt(&recv_cipher_ctx, payload_bytes, payload_size);
    delete[] payload_bytes;

    uint8_t mac[4];
    conn.read_fully(mac, sizeof(mac));

    uint8_t expected_mac[4];
    shn_finish(&recv_cipher_ctx, expected_mac, sizeof(expected_mac));
    if (std::memcmp(mac, expected_mac, 4) != 0) {
        // TODO: Handle error!
        std::cout << "MACs don't match!" << std::endl;
    }

    return {cmd, payload_bytes, (size_t) payload_size};
}
