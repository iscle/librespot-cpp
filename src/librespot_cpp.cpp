//
// Created by Iscle on 03/02/2021.
//

#include <spdlog/spdlog.h>
#include "librespot_cpp.h"
#include "version.h"
#include "core/session.h"

void LibrespotCpp::start() {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    spdlog::info("Welcome to librespot-c++!");

    std::unique_ptr<Session> session = Session::create();
    session->connect();

    spotify::LoginCredentials login_credentials;
    login_credentials.set_typ(spotify::AUTHENTICATION_USER_PASS);
    login_credentials.set_username("albertiscle9@gmail.com");
    login_credentials.set_auth_data("");
    session->authenticate(login_credentials);

    google::protobuf::ShutdownProtobufLibrary();
}
