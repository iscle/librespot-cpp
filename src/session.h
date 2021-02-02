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
    std::unique_ptr<CipherPair> cipher_pair;
    std::unique_ptr<utils::ConnectionHolder> conn;

    explicit Session(const std::string &addr);

    ~Session();

    static std::unique_ptr<Session> create();

    void connect();

    void authenticate(const spotify::LoginCredentials &);

    const std::unique_ptr<MercuryClient> &mercury() const;

    const std::unique_ptr<AudioKeyManager> &audio_key() const;

    const std::unique_ptr<ChannelManager> &channel() const;

private:
    class Configuration {

    };

    std::atomic<bool> auth_lock;
    spotify::APWelcome ap_welcome;
    std::unique_ptr<std::thread> receiver;
    std::unique_ptr<MercuryClient> mercury_client;
    std::unique_ptr<AudioKeyManager> audio_key_manager;
    std::unique_ptr<ChannelManager> channel_manager;

    void authenticate_partial(spotify::LoginCredentials &credentials, bool remove_lock);

    void send_unchecked(Packet::Type cmd, std::vector<uint8_t> &payload);

    void send_unchecked(Packet::Type cmd, std::string &payload);
};

#endif //LIBRESPOT_C_SESSION_H
