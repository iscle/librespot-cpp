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
    zeroconf.start([&session](std::string &device_id, std::string &username, std::vector<uint8_t> &payload) {
        if (session.running) return; // TODO: Fix me!
        SPDLOG_INFO("Zeroconf callback called!");
        auto credentials = utils::decode_auth_blob(device_id, username, payload);
        session.authenticate(credentials);
    });

    SPDLOG_INFO("Outside! :)");

    while (1);

    google::protobuf::ShutdownProtobufLibrary();
}
