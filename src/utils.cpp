//
// Created by Iscle on 31/01/2021.
//

#include "utils.h"
#include "version.h"
#include "crypto/aes.h"
#include "crypto/pbkdf_2.h"
#include "crypto/base_64.h"
#include "crypto/sha_1.h"
#include <sys/socket.h>
#include <iostream>
#include <unistd.h>
#include <netdb.h>
#include <memory>

void utils::ByteArray::write_int(int data) {
    write_byte((data >> 24) & 0xFF);
    write_byte((data >> 16) & 0xFF);
    write_byte((data >> 8) & 0xFF);
    write_byte((data >> 0) & 0xFF);
}

void utils::ByteArray::write_byte(uint8_t data) {
    push_back(data);
}

void utils::ByteArray::write(const std::string &data) {
    for (char i : data)
        push_back(i);
}

void utils::ByteArray::write(const std::vector<uint8_t> &data) {
    for (uint8_t i : data)
        push_back(i);
}

void utils::ByteArray::write(const char *data, size_t length) {
    for (size_t i = 0; i < length; i++)
        push_back(data[i]);
}

void utils::ByteArray::write_short(short data) {
    write_byte(data >> 8);
    write_byte(data >> 0);
}

std::string utils::generate_device_id() {
    return "209031ee9cc724ce46a6c4bf9140c70c4a9202c8";
}

utils::ByteBuffer::ByteBuffer(std::vector<uint8_t> &vector) :
        vector(vector), pos(0) {

}

utils::ByteBuffer::ByteBuffer(std::string &string) :
        vector(std::vector<uint8_t>(string.begin(), string.end())), pos(0) {

}

uint8_t utils::ByteBuffer::get() {
    uint8_t data = 0;
    data |= ((uint8_t) vector[pos++]) << 0;
    return data;
}

short utils::ByteBuffer::get_short() {
    short data = 0;
    data |= ((short) vector[pos++]) << 8;
    data |= ((short) vector[pos++]) << 0;
    return data;
}

int utils::ByteBuffer::get_int() {
    int data = 0;
    data |= ((int) vector[pos++]) << 24;
    data |= ((int) vector[pos++]) << 16;
    data |= ((int) vector[pos++]) << 8;
    data |= ((int) vector[pos++]) << 0;
    return data;
}

long utils::ByteBuffer::get_long() {
    long data = 0;
    data |= ((long) vector[pos++]) << 56;
    data |= ((long) vector[pos++]) << 48;
    data |= ((long) vector[pos++]) << 40;
    data |= ((long) vector[pos++]) << 32;
    data |= ((long) vector[pos++]) << 24;
    data |= ((long) vector[pos++]) << 16;
    data |= ((long) vector[pos++]) << 8;
    data |= ((long) vector[pos++]) << 0;
    return data;
}

std::vector<uint8_t> utils::ByteBuffer::get(size_t size) {
    std::vector<uint8_t> data(size);

    for (size_t i = 0; i < size; i++)
        data[i] = vector[pos++];

    return std::move(data);
}

rapidjson::Value utils::json_string(std::string &str, rapidjson::Document::AllocatorType &allocator) {
    rapidjson::Value str_value;
    str_value.SetString(str.c_str(), str.size(), allocator);
    return std::move(str_value);
}

int utils::read_blob_int(utils::ByteBuffer &buffer) {
    int lo = buffer.get();
    if ((lo & 0x80) == 0) return lo;
    int hi = buffer.get();
    return hi << 7 | (lo & 0x7f);
}

spotify::LoginCredentials utils::decode_auth_blob(std::string &device_id, std::string &username, std::vector<uint8_t> &payload) {
    auto encrypted_blob = Base64::Decode(payload);

    class SHA1 sha;
    sha.init();
    sha.update(device_id);
    std::vector<uint8_t> secret;
    sha.final(secret);

    std::vector<uint8_t> base_key(20);
    PBKDF2::hmac_sha1(secret, username, 256, base_key);

    utils::ByteArray key_ba;
    sha.init();
    sha.update(base_key);
    std::vector<uint8_t> tmp;
    sha.final(tmp);
    key_ba.write(tmp);
    key_ba.write_int(20);

    AES aes(AES::Type::AES_192_ECB);
    aes.init(key_ba);
    aes.set_padding(0);
    aes.update(encrypted_blob);
    aes.final(encrypted_blob);

    int l = encrypted_blob.size();
    for (int i = 0; i < l - 16; i++)
        encrypted_blob[l - i - 1] ^= encrypted_blob[l - i - 16 - 1];

    utils::ByteBuffer blob(encrypted_blob);
    blob.get();
    int len = utils::read_blob_int(blob);
    blob.get(len);
    blob.get();

    int type_int = utils::read_blob_int(blob);
    if (!spotify::AuthenticationType_IsValid(type_int)) {

    }
    auto type = static_cast<spotify::AuthenticationType>(type_int);

    blob.get();

    len = utils::read_blob_int(blob);
    auto auth_data = blob.get(len);

    spotify::LoginCredentials credentials;
    credentials.set_username(username);
    credentials.set_typ(type);
    credentials.set_auth_data(auth_data.data(), auth_data.size());

    return credentials;
}