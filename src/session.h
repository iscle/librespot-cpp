//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_SESSION_H
#define LIBRESPOT_C_SESSION_H

#include <string>
#include <vector>
#include <proto/authentication.pb.h>
#include "crypto/cipher_pair.h"
#include "utils.h"

class Session {
public:
    static Session *create();
    void connect();
    void authenticate(const spotify::LoginCredentials&);

private:
    class Configuration {

    };

    utils::ConnectionHolder conn;
    std::atomic<bool> auth_lock;
    CipherPair *cipher_pair;

    Session(const std::string &addr);
    void authenticate_partial(spotify::LoginCredentials& credentials, bool remove_lock);
    void send_unchecked(Packet::Type cmd, uint8_t *payload, size_t payload_size);
};

#endif //LIBRESPOT_C_SESSION_H
