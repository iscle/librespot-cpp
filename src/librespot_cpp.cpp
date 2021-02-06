//
// Created by Iscle on 03/02/2021.
//

#include <spdlog/spdlog.h>
#include "librespot_cpp.h"
#include "version.h"
#include "core/session.h"
#include "core/ap_resolver.h"
#include "network/zeroconf.h"

void LibrespotCpp::start() {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %s:%# - %v");
    SPDLOG_INFO("Welcome to librespot-c++!");

    auto connection = std::make_shared<Connection>(APResolver::get_instance().get_accesspoint());
    Session session(connection);
    session.connect();

    Zeroconf zeroconf;
    zeroconf.start([&session](std::vector<uint8_t> &payload) {
        SPDLOG_INFO("Callback called!");
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
