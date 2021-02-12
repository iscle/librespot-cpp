//
// Created by Iscle on 31/01/2021.
//

#ifndef LIBRESPOT_C_UTILS_H
#define LIBRESPOT_C_UTILS_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <rapidjson/document.h>
#include "version.h"
#include "utils/byte_buffer.h"

std::string generate_device_id();

rapidjson::Value json_string(std::string &str, rapidjson::Document::AllocatorType &allocator);

int read_blob_int(ByteBuffer &buffer);

spotify::LoginCredentials decode_auth_blob(std::string &device_id, std::string &username, std::vector<uint8_t> &payload);

uint64_t htonll(uint64_t x);
uint64_t ntohll(uint64_t x);

#endif //LIBRESPOT_C_UTILS_H
