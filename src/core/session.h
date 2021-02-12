//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_SESSION_H
#define LIBRESPOT_C_SESSION_H

#include <string>
#include <vector>
#include <proto/authentication.pb.h>
#include <thread>
#include <proto/keyexchange.pb.h>
#include "../crypto/cipher_pair.h"
#include "../utils.h"
#include "../mercury/mercury_client.h"
#include "../audio/audio_key_manager.h"
#include "../audio/storage/channel_manager.h"
#include "../crypto/diffie_hellman.h"
#include "../dealer/dealer_client.h"
#include "event_service.h"
#include "../delayed_task.h"
#include "../utils/byte_array.h"

class Session {
public:
    explicit Session(const std::string& accesspoint);

    ~Session();

    void connect();

    void authenticate(spotify::LoginCredentials &credentials);

    void send(Packet::Type cmd, std::vector<uint8_t> &payload);

    const std::unique_ptr<MercuryClient> &mercury() const;

    const std::unique_ptr<AudioKeyManager> &audio_key() const;

    const std::unique_ptr<ChannelManager> &channel() const;

    std::string country_code;
    bool running;

    void start();

private:
    class Configuration {

    };

    DiffieHellman keys;
    //Inner inner;
    //ScheduledExecutorService scheduler;
    std::atomic<bool> auth_lock;
    std::map<std::string, std::string> user_attributes;
    std::thread receiver;
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
    volatile bool closed;
    volatile bool closing;
    DelayedTask scheduled_reconnect;
    Connection conn;
    std::unique_ptr<CipherPair> cipher_pair;

    void send_unchecked(Packet::Type cmd, std::vector<uint8_t> &payload);

    void send_unchecked(Packet::Type cmd, std::string &payload);

    void send_client_hello(ByteArray &acc, DiffieHellman &dh);

    static void check_gs_signature(spotify::APResponseMessage &response);

    static std::vector<uint8_t>
    solve_challenge(ByteArray &acc, DiffieHellman &dh, spotify::APResponseMessage &response,
                    ByteArray &data);

    void send_challenge_response(std::vector<uint8_t> &challenge);

    void read_connection_status();

    void packet_receiver();

    void reconnect();

};

#endif //LIBRESPOT_C_SESSION_H
