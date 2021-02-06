//
// Created by Iscle on 04/02/2021.
//

#ifndef LIBRESPOT_CPP_ZEROCONF_H
#define LIBRESPOT_CPP_ZEROCONF_H

#include <rapidjson/document.h>
#include <netdb.h>
#include <unistd.h>
#include <cpp-httplib/httplib.h>
#include <avahi-client/publish.h>
#include "../crypto/diffie_hellman.h"

class Zeroconf {
public:
    int listen_port;
    AvahiEntryGroup *group = nullptr;

    Zeroconf();

    Zeroconf(int listen_port);

    ~Zeroconf();

    void start_server();

private:
    DiffieHellman keys;
    httplib::Server svr;
    std::thread server_thread;

    void listen();

    void register_avahi();

    std::string get_info(std::string device_id, std::string remote_name, std::string active_user,
                         std::string public_key, std::string device_type);

    static std::string get_successful_add_user();

};


#endif //LIBRESPOT_CPP_ZEROCONF_H