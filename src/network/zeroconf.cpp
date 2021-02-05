//
// Created by Iscle on 04/02/2021.
//

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <memory>
#include <netdb.h>
#include <thread>
#include <cstdlib>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <iostream>
#include <avahi-common/simple-watch.h>
#include <spdlog/spdlog.h>
#include "zeroconf.h"

#define MIN_PORT 1024
#define MAX_PORT 65536
#define EOL {'\r', '\n'};

static AvahiSimplePoll *simple_poll = nullptr;

Zeroconf::Zeroconf() {
    listen_port = 10374;
}

Zeroconf::Zeroconf(int listen_port) : listen_port(listen_port) {
}

Zeroconf::~Zeroconf() {
    if (svr.is_running()) svr.stop();
    server_thread.join();
}

void Zeroconf::listen() {
    SPDLOG_INFO("Starting zeroconf server at port {}", listen_port);

    svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
        if (req.get_param_value("action") == "getInfo") {
            SPDLOG_DEBUG("Test debug log 1");
            SPDLOG_INFO("getInfo requested from {}:{}", req.remote_addr, req.remote_port);
            SPDLOG_DEBUG("Test debug log 2");

            auto info = get_default_info();
            rapidjson::Document::AllocatorType &allocator = info->GetAllocator();

            rapidjson::Value pkey;
            info->AddMember("deviceID", "209031ee9cc724ce46a6c4bf9140c70c4a9202c8", allocator);
            info->AddMember("remoteName", "librespot-c++", allocator);
            pkey.SetString(reinterpret_cast<const char *>(this->keys.get_public_key()), this->keys.get_public_key_length(), allocator);
            info->AddMember("publicKey", pkey, allocator);
            info->AddMember("deviceType", "SPEAKER", allocator);
            info->AddMember("activeUser", "", allocator);

            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            info->Accept(writer);
            res.set_content(buffer.GetString(), buffer.GetLength(), "application/json");
        }
    });
    svr.Post("/", [&](const httplib::Request &req, httplib::Response &res) {
        if (!req.has_param("action")) return;

        auto action = req.get_param_value("action");
        if (action == "addUser") {
            SPDLOG_DEBUG("addUser requested from {}:{}", req.remote_addr, req.remote_port);
        }
    });

    server_thread = std::thread([this]() {
        svr.listen("0.0.0.0", listen_port);
    });
}

static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata) {
    ((Zeroconf *) userdata)->group = g;
    /* Called whenever the entry group state changes */
    if (state == AVAHI_ENTRY_GROUP_FAILURE) {
        fprintf(stderr, "Entry group failure: %s\n", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
        avahi_simple_poll_quit(simple_poll);
    }
}

static void create_services(AvahiClient *c, Zeroconf *instance) {
    int ret;

    /* If this is the first time we're called, let's create a new
     * entry group if necessary */
    if (!instance->group && !(instance->group = avahi_entry_group_new(c, entry_group_callback, instance))) {
        fprintf(stderr, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(c)));
        goto fail;
    }
    /* If the group is empty (either because it was just created, or
     * because it was reset previously, add our entries.  */
    if (avahi_entry_group_is_empty(instance->group)) {
        if ((ret = avahi_entry_group_add_service(instance->group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
                                                 static_cast<AvahiPublishFlags>(0), "spotify-connect", "_spotify-connect._tcp", nullptr, nullptr, instance->listen_port, "CPath=/", "VERSION=1.0", "Stack=SP", nullptr)) < 0) {
            fprintf(stderr, "Failed to add _spotify-connect._tcp service: %s\n", avahi_strerror(ret));
            goto fail;
        }
        if ((ret = avahi_entry_group_commit(instance->group)) < 0) {
            fprintf(stderr, "Failed to commit entry group: %s\n", avahi_strerror(ret));
            goto fail;
        }
    }
    return;
    fail:
    avahi_simple_poll_quit(simple_poll);
}

static void client_callback(AvahiClient *c, AvahiClientState state, void *userdata) {
    auto *instance = static_cast<Zeroconf *>(userdata);
    /* Called whenever the client or server state changes */
    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            /* The server has startup successfully and registered its host
             * name on the network, so it's time to create our services */
            create_services(c, instance);
            break;
        case AVAHI_CLIENT_FAILURE:
            fprintf(stderr, "Client failure: %s\n", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(simple_poll);
            break;
        case AVAHI_CLIENT_S_COLLISION:
            /* Let's drop our registered services. When the server is back
             * in AVAHI_SERVER_RUNNING state we will register them
             * again with the new host name. */
        case AVAHI_CLIENT_S_REGISTERING:
            fprintf(stdout, "Client registering!\n");
            if (instance->group)
                avahi_entry_group_reset(instance->group);
            break;
        case AVAHI_CLIENT_CONNECTING:
            fprintf(stdout, "Client connecting!\n");
            break;
    }
}

void Zeroconf::register_avahi() {
    SPDLOG_DEBUG("Registering avahi...");
    /* Allocate main loop object */
    simple_poll = avahi_simple_poll_new();
    if (simple_poll == nullptr) {
        SPDLOG_ERROR("Failed to create simple poll object!");
        return;
    }

    /* Allocate a new client */
    int error;
    AvahiClient *client = avahi_client_new(avahi_simple_poll_get(simple_poll),
                                           static_cast<AvahiClientFlags>(0), client_callback, this, &error);
    if (client == nullptr) {
        SPDLOG_ERROR("Failed to create client: {}", avahi_strerror(error));
        avahi_simple_poll_free(simple_poll);
        return;
    }

    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    avahi_client_free(client);
    avahi_simple_poll_free(simple_poll);
}

void Zeroconf::start_server() {
    listen();
    register_avahi();
}

std::unique_ptr<rapidjson::Document> Zeroconf::get_default_info() {
    auto info = std::make_unique<rapidjson::Document>();
    rapidjson::Document::AllocatorType &allocator = info->GetAllocator();

    info->SetObject();

    info->AddMember("status", 101, allocator);
    info->AddMember("statusString", "OK", allocator);
    info->AddMember("spotifyError", 0, allocator);
    info->AddMember("version", "2.7.1", allocator);
    info->AddMember("libraryVersion", "?.?.?", allocator);
    info->AddMember("accountReq", "PREMIUM", allocator);
    info->AddMember("brandDisplayName", "librespot-org", allocator);
    info->AddMember("modelDisplayName", "librespot-c++", allocator);
    info->AddMember("voiceSupport", "NO", allocator);
    info->AddMember("availability", "", allocator);
    info->AddMember("productID", 0, allocator);
    info->AddMember("tokenType", "default", allocator);
    info->AddMember("groupStatus", "NONE", allocator);
    info->AddMember("resolverVersion", "0", allocator);
    info->AddMember("scope", "streaming,client-authorization-universal", allocator);

    return std::move(info);
}

std::unique_ptr<rapidjson::Document> Zeroconf::get_successful_add_user() {
    auto info = std::make_unique<rapidjson::Document>();
    rapidjson::Document::AllocatorType &allocator = info->GetAllocator();

    info->SetObject();

    info->AddMember("status", 101, allocator);
    info->AddMember("statusString", "OK", allocator);
    info->AddMember("spotifyError", 0, allocator);

    return std::move(info);
}
