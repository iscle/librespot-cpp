//
// Created by Iscle on 31/01/2021.
//

#include <memory>
#include "packet.h"

Packet::Packet(uint8_t cmd, std::vector<uint8_t> &payload) {
    this->cmd = cmd;
    this->payload = payload;
}
