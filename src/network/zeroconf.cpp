//
// Created by Iscle on 04/02/2021.
//

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <memory>
#include <thread>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <spdlog/spdlog.h>
#include "zeroconf.h"
#include "../utils.h"
#include "../crypto/base_64.h"
#include "../crypto/aes.h"
#include "../crypto/hmac_sha_1.h"
#include "../crypto/sha_1.h"

#define MIN_PORT 1024
#define MAX_PORT 65536

Zeroconf::Zeroconf() {
    listen_port = 10374;
    group = nullptr;
    simple_poll = nullptr;
}

Zeroconf::Zeroconf(int listen_port) : listen_port(listen_port) {
    group = nullptr;
    simple_poll = nullptr;
}

Zeroconf::~Zeroconf() {
    avahi_simple_poll_quit(simple_poll);
    avahi_thread.join();
    if (svr.is_running()) svr.stop();
    server_thread.join();
}

void Zeroconf::listen(std::function<void(std::string &device_id, std::string &username, std::vector<uint8_t> &payload)> &callback) {
    SPDLOG_INFO("Starting zeroconf server at port {}", listen_port);

    svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
        auto action = req.get_param_value("action");
        if (action == "getInfo") {
            SPDLOG_DEBUG("getInfo requested from {}:{}", req.remote_addr, req.remote_port);

            auto info = get_info(generate_device_id(), "librespot-c++", "",
                                 Base64::Encode(this->keys.get_public_key(), this->keys.get_public_key_length()),
                                 "AUTOMOBILE");
            res.set_content(info, "application/json");
        } else if (action == "resetUsers") {
            SPDLOG_DEBUG("Received resetUsers on GET handler!");
        }
    });
    svr.Post("/", [&](const httplib::Request &req, httplib::Response &res) {
        auto action = req.get_param_value("action");
        if (action == "addUser") {
            SPDLOG_DEBUG("addUser requested from {}:{}", req.remote_addr, req.remote_port);

            auto device_id = generate_device_id();
            auto blob = Base64::Decode(req.get_param_value("blob"));
            auto shared_key = keys.compute_shared_key(Base64::Decode(req.get_param_value("clientKey")));
            auto device_name = req.get_param_value("deviceName");
            auto user_name = req.get_param_value("userName");

            auto iv = std::vector<uint8_t>(blob.begin(), blob.begin() + 16);
            auto encrypted = std::vector<uint8_t>(blob.begin() + 16, blob.end() - 20);
            auto checksum = std::vector<uint8_t>(blob.end() - 20, blob.end());

            int ret;

            // Calculate base key
            class SHA1 sha;
            sha.init();
            sha.update(shared_key);
            std::vector<uint8_t> base_key;
            ret = sha.final(base_key);
            if (ret != 1) {
                SPDLOG_ERROR("Failed to calculate base key!");
                return;
            }
            base_key.resize(16);

            // Calculate checksum key
            HMAC_SHA1 hmac;
            hmac.init(base_key);
            std::string msg = "checksum";
            hmac.update(msg);
            std::vector<uint8_t> checksum_key;
            ret = hmac.final(checksum_key);
            if (ret != 1) {
                SPDLOG_ERROR("Failed to calculate checksum key!");
                return;
            }

            // Calculate encryption key
            hmac.init(base_key);
            msg = "encryption";
            hmac.update(msg);
            std::vector<uint8_t> encryption_key;
            ret = hmac.final(encryption_key);
            if (ret != 1) {
                SPDLOG_ERROR("Failed to calculate encryption key!");
                return;
            }
            encryption_key.resize(16);

            // Calculate mac
            hmac.init(checksum_key);
            hmac.update(encrypted);
            std::vector<uint8_t> mac;
            ret = hmac.final(mac);
            if (ret != 1) {
                SPDLOG_ERROR("Failed to calculate mac!");
                return;
            }

            if (mac != checksum) {
                SPDLOG_ERROR("Mac and checksum don't match!");
                res.status = 500;
                return;
            }

            AES aes128(AES::Type::AES_128_CTR);
            aes128.init(encryption_key, iv);
            aes128.set_padding(0);
            aes128.update(encrypted);
            ret = aes128.final(encrypted);
            if (ret != 1) {
                SPDLOG_ERROR("Failed to decrypt data!");
                return;
            }

            res.set_content(get_successful_add_user(), "application/json");

            callback(device_id, user_name, encrypted);
        } else if (action == "resetUsers") {
            SPDLOG_DEBUG("Received resetUsers on POST handler!");
        }
    });

    server_thread = std::thread([this]() {
        svr.listen("0.0.0.0", listen_port);
    });
}

static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata) {
    auto *instance = static_cast<Zeroconf *>(userdata);
    instance->group = g;
    if (state == AVAHI_ENTRY_GROUP_FAILURE ||
        state == AVAHI_ENTRY_GROUP_COLLISION) {
        SPDLOG_ERROR("An entry group error occurred.");
        avahi_simple_poll_quit(instance->simple_poll);
    }
}

static void create_services(AvahiClient *c, Zeroconf *instance) {
    if (instance->group == nullptr) {
        instance->group = avahi_entry_group_new(c, entry_group_callback, instance);
        if (instance->group == nullptr) {
            SPDLOG_ERROR("Failed to create new entry group: {}", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(instance->simple_poll);
            return;
        }
    }

    if (avahi_entry_group_is_empty(instance->group)) {
        int ret = avahi_entry_group_add_service(instance->group,
                                            AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
                                            static_cast<AvahiPublishFlags>(0),
                                            "spotify-connect","_spotify-connect._tcp",
                                            nullptr, nullptr, instance->listen_port,
                                            "CPath=/", "VERSION=1.0", "Stack=SP", nullptr);
        if (ret < 0) {
            SPDLOG_ERROR("Failed to add _spotify-connect._tcp service: {}", avahi_strerror(ret));
            avahi_simple_poll_quit(instance->simple_poll);
            return;
        }

        ret = avahi_entry_group_commit(instance->group);
        if (ret < 0) {
            SPDLOG_ERROR("Failed to commit entry group: {}", avahi_strerror(ret));
            avahi_simple_poll_quit(instance->simple_poll);
            return;
        }
    }
}

static void client_callback(AvahiClient *c, AvahiClientState state, void *userdata) {
    auto *instance = static_cast<Zeroconf *>(userdata);

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            create_services(c, instance);
            break;
        case AVAHI_CLIENT_FAILURE:
            SPDLOG_ERROR("Client failure: {}", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(instance->simple_poll);
            break;
        case AVAHI_CLIENT_S_COLLISION:
        case AVAHI_CLIENT_S_REGISTERING:
            if (instance->group)
                avahi_entry_group_reset(instance->group);
            break;
    }
}

void Zeroconf::register_avahi() {
    simple_poll = avahi_simple_poll_new();
    if (simple_poll == nullptr) {
        SPDLOG_ERROR("Failed to create simple poll object!");
        return;
    }

    int error;
    AvahiClient *client = avahi_client_new(avahi_simple_poll_get(simple_poll),
                                           static_cast<AvahiClientFlags>(0),
                                           client_callback, this, &error);
    if (client == nullptr) {
        SPDLOG_ERROR("Failed to create client: {}", avahi_strerror(error));
        avahi_simple_poll_free(simple_poll);
        return;
    }

    avahi_thread = std::thread([this, client] {
        avahi_simple_poll_loop(simple_poll); // Blocking!
        avahi_client_free(client);
        avahi_simple_poll_free(simple_poll);
    });
}

void Zeroconf::start(std::function<void(std::string &device_id, std::string &username, std::vector<uint8_t> &payload)> callback) {
    listen(callback);
    register_avahi();
}

void Zeroconf::stop() {

}

std::string
Zeroconf::get_info(std::string device_id, std::string remote_name, std::string active_user, std::string public_key,
                   std::string device_type) {
    auto info = std::make_unique<rapidjson::Document>();
    rapidjson::Document::AllocatorType &allocator = info->GetAllocator();

    info->SetObject();

    info->AddMember("status", 101, allocator);
    info->AddMember("statusString", "OK", allocator);
    info->AddMember("spotifyError", 0, allocator);
    info->AddMember("version", "2.7.1", allocator);
    info->AddMember("deviceID", json_string(device_id, allocator), allocator);
    info->AddMember("remoteName", json_string(remote_name, allocator), allocator);
    info->AddMember("activeUser", json_string(active_user, allocator), allocator);
    info->AddMember("publicKey", json_string(public_key, allocator), allocator);
    info->AddMember("deviceType", json_string(device_type, allocator), allocator);
    info->AddMember("libraryVersion", "?.?.?", allocator); // TODO: Fix this value!
    info->AddMember("accountReq", "PREMIUM", allocator);
    info->AddMember("brandDisplayName", "librespot-org", allocator);
    info->AddMember("modelDisplayName", "librespot-c++", allocator);
    info->AddMember("resolverVersion", 0, allocator); // TODO: Fix this value!
    info->AddMember("groupStatus", "", allocator); // TODO: Fix this value!
    info->AddMember("tokenType", "default", allocator);
    info->AddMember("clientID", "", allocator); // TODO: Fix this value!
    info->AddMember("productID", 0, allocator); // TODO: Fix this value!
    info->AddMember("scope", "streaming,client-authorization-universal", allocator);
    info->AddMember("availability", "", allocator); // TODO: Fix this value!
    info->AddMember("voiceSupport", "NO", allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    info->Accept(writer);

    return std::string(buffer.GetString(), buffer.GetLength());
}

std::string Zeroconf::get_successful_add_user() {
    auto info = std::make_unique<rapidjson::Document>();
    rapidjson::Document::AllocatorType &allocator = info->GetAllocator();

    info->SetObject();

    info->AddMember("status", 101, allocator);
    info->AddMember("statusString", "OK", allocator);
    info->AddMember("spotifyError", 0, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    info->Accept(writer);

    return std::string(buffer.GetString(), buffer.GetLength());
}
