//
// Created by Iscle on 31/01/2021.
//

#include "packet.h"

Packet::Packet(uint8_t cmd, uint8_t *payload, size_t payload_size) {
    this->cmd = cmd;
    this->payload = payload;
    this->payload_size = payload_size;
}

bool Packet::is(Packet::Type type) const {
    return cmd == type;
}
