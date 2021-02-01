//
// Created by Iscle on 31/01/2021.
//

#include <memory>
#include "packet.h"

Packet::Packet(uint8_t cmd, std::shared_ptr<uint8_t[]> &payload, size_t payload_size) {
    this->cmd = cmd;
    this->payload = payload;
    this->payload_size = payload_size;
}
