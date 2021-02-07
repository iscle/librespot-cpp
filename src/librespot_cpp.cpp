//
// Created by Iscle on 03/02/2021.
//

#include <spdlog/spdlog.h>
#include "librespot_cpp.h"
#include "version.h"
#include "core/session.h"
#include "core/ap_resolver.h"
#include "network/zeroconf.h"
#include "crypto/base_64.h"
#include "crypto/sha_1.h"
#include "crypto/pbkdf_2.h"
#include "crypto/aes.h"

void LibrespotCpp::start() {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %s:%# - %v");
    SPDLOG_INFO("Welcome to librespot-c++!");

    auto connection = std::make_shared<Connection>(APResolver::get_instance().get_accesspoint());
    Session session(connection);
    session.connect();

    Zeroconf zeroconf;
    zeroconf.start([&session](std::string &device_id, std::string &username, std::vector<uint8_t> &payload) {
        SPDLOG_INFO("Callback called!");
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

        session.authenticate(credentials);
    });

    SPDLOG_INFO("Outside! :)");

    while (1);

    spotify::LoginCredentials login_credentials;
    login_credentials.set_typ(spotify::AUTHENTICATION_USER_PASS);
    login_credentials.set_username("albertiscle9@gmail.com");
    login_credentials.set_auth_data("");

    session.authenticate(login_credentials);

    google::protobuf::ShutdownProtobufLibrary();
}
