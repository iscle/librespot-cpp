//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_SESSION_H
#define LIBRESPOT_C_SESSION_H

#include <string>
#include <vector>
#include <proto/authentication.pb.h>
#include <thread>
#include "crypto/cipher_pair.h"
#include "utils.h"
#include "mercury/mercury_client.h"
#include "audio/audio_key_manager.h"
#include "audio/storage/channel_manager.h"

class Session {
public:
    bool running;
    CipherPair *cipher_pair;
    utils::ConnectionHolder conn;

    static Session *create();

    void connect();

    void authenticate(const spotify::LoginCredentials &);

    MercuryClient *mercury() const;
    AudioKeyManager *audio_key() const;
    ChannelManager *channel() const;

private:
    class Configuration {

    };

    std::atomic<bool> auth_lock;
    spotify::APWelcome ap_welcome;
    std::thread *receiver;
    MercuryClient *mercury_client;
    AudioKeyManager *audio_key_manager;
    ChannelManager *channel_manager;

    Session(const std::string &addr);

    void authenticate_partial(spotify::LoginCredentials &credentials, bool remove_lock);

    void send_unchecked(Packet::Type cmd, uint8_t *payload, size_t payload_size);
};

#endif //LIBRESPOT_C_SESSION_H
