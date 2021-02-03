//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_SESSION_H
#define LIBRESPOT_C_SESSION_H

#include <string>
#include <vector>
#include <proto/authentication.pb.h>
#include <thread>
#include "../crypto/cipher_pair.h"
#include "../utils.h"
#include "../mercury/mercury_client.h"
#include "../audio/audio_key_manager.h"
#include "../audio/storage/channel_manager.h"
#include "../crypto/diffie_hellman.h"
#include "../dealer/dealer_client.h"
#include "event_service.h"

class Session {
public:
    bool running;
    std::unique_ptr<ConnectionHolder> conn;
    std::unique_ptr<CipherPair> cipher_pair;

    explicit Session(const std::string &addr);

    ~Session();

    static std::unique_ptr<Session> create();

    void connect();

    void authenticate(const spotify::LoginCredentials &);

    void send(Packet::Type &cmd, std::vector<uint8_t> &payload);

    const std::unique_ptr<MercuryClient> &mercury() const;

    const std::unique_ptr<AudioKeyManager> &audio_key() const;

    const std::unique_ptr<ChannelManager> &channel() const;

private:
    class Configuration {

    };

    DiffieHellman keys;
    //Inner inner;
    //ScheduledExecutorService scheduler;
    std::atomic<bool> auth_lock;
    std::map<std::string, std::string> user_attributes;
    std::unique_ptr<std::thread> receiver;
    spotify::APWelcome ap_welcome;
    std::unique_ptr<MercuryClient> mercury_client;
    std::unique_ptr<AudioKeyManager> audio_key_manager;
    std::unique_ptr<ChannelManager> channel_manager;
    //std::unique_ptr<TokenProvider> token_provider;
    //std::unique_ptr<CdnManager> cdn_manager;
    //std::unique_ptr<CacheManager> cache_manager;
    std::unique_ptr<DealerClient> dealer;
    //std::unique_ptr<ApiClient> api;
    //std::unique_ptr<SearchManager> search;
    //std::unique_ptr<PlayableContentFeeder> content_feeder;
    std::unique_ptr<EventService> event_service;
    std::string country_code;
    volatile bool closed;
    volatile bool closing;

    void authenticate_partial(spotify::LoginCredentials &credentials, bool remove_lock);

    void send_unchecked(Packet::Type cmd, std::vector<uint8_t> &payload);

    void send_unchecked(Packet::Type cmd, std::string &payload);
};

#endif //LIBRESPOT_C_SESSION_H
