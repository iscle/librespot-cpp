//
// Created by Iscle on 31/01/2021.
//

#include "utils.h"
#include "crypto/aes.h"
#include "crypto/pbkdf_2.h"
#include "crypto/base_64.h"
#include "crypto/sha_1.h"
#include "utils/byte_array.h"
#include <iostream>
#include <netdb.h>

std::string generate_device_id() {
    return "209031ee9cc724ce46a6c4bf9140c70c4a9202c8";
}

rapidjson::Value json_string(std::string &str, rapidjson::Document::AllocatorType &allocator) {
    rapidjson::Value str_value;
    str_value.SetString(str.c_str(), str.size(), allocator);
    return std::move(str_value);
}

int read_blob_int(ByteBuffer &buffer) {
    int lo = buffer.get();
    if ((lo & 0x80) == 0) return lo;
    int hi = buffer.get();
    return hi << 7 | (lo & 0x7f);
}

spotify::LoginCredentials
decode_auth_blob(std::string &device_id, std::string &username, std::vector<uint8_t> &payload) {
    auto encrypted_blob = Base64::Decode(payload);

    class SHA1 sha;
    sha.init();
    sha.update(device_id);
    std::vector<uint8_t> secret;
    sha.final(secret);

    std::vector<uint8_t> base_key(20);
    PBKDF2::hmac_sha1(secret, username, 256, base_key);

    ByteArray key_ba;
    sha.init();
    sha.update(base_key);
    std::vector<uint8_t> tmp;
    sha.final(tmp);
    key_ba.write(tmp);
    key_ba.write_int(htonl(20));

    AES aes(AES::Type::AES_192_ECB);
    aes.init(key_ba);
    aes.set_padding(0);
    aes.update(encrypted_blob);
    aes.final(encrypted_blob);

    int l = encrypted_blob.size();
    for (int i = 0; i < l - 16; i++)
        encrypted_blob[l - i - 1] ^= encrypted_blob[l - i - 16 - 1];

    ByteBuffer blob(encrypted_blob);
    blob.get();
    int len = read_blob_int(blob);
    blob.get(len);
    blob.get();

    int type_int = read_blob_int(blob);
    if (!spotify::AuthenticationType_IsValid(type_int)) {

    }
    auto type = static_cast<spotify::AuthenticationType>(type_int);

    blob.get();

    len = read_blob_int(blob);
    auto auth_data = blob.get(len);

    spotify::LoginCredentials credentials;
    credentials.set_username(username);
    credentials.set_typ(type);
    credentials.set_auth_data(auth_data.data(), auth_data.size());

    return credentials;
}

uint64_t htonll(uint64_t x) {
#if BYTE_ORDER == LITTLE_ENDIAN
    return bswap_64(x);
#else
    return x;
#endif
}

uint64_t ntohll(uint64_t x) {
    return htonll(x);
}