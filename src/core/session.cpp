//
// Created by Iscle on 26/01/2021.
//

#include "session.h"
#include "../version.h"
#include "ap_resolver.h"
#include "../crypto/diffie_hellman.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static constexpr uint8_t SERVER_KEY[] = {
        0xac, 0xe0, 0x46, 0x0b, 0xff, 0xc2, 0x30, 0xaf, 0xf4, 0x6b, 0xfe, 0xc3, 0xbf, 0xbf, 0x86, 0x3d, 0xa1, 0x91,
        0xc6, 0xcc, 0x33, 0x6c, 0x93, 0xa1, 0x4f, 0xb3, 0xb0, 0x16, 0x12, 0xac, 0xac, 0x6a, 0xf1, 0x80, 0xe7, 0xf6,
        0x14, 0xd9, 0x42, 0x9d, 0xbe, 0x2e, 0x34, 0x66, 0x43, 0xe3, 0x62, 0xd2, 0x32, 0x7a, 0x1a, 0x0d, 0x92, 0x3b,
        0xae, 0xdd, 0x14, 0x02, 0xb1, 0x81, 0x55, 0x05, 0x61, 0x04, 0xd5, 0x2c, 0x96, 0xa4, 0x4c, 0x1e, 0xcc, 0x02,
        0x4a, 0xd4, 0xb2, 0x0c, 0x00, 0x1f, 0x17, 0xed, 0xc2, 0x2f, 0xc4, 0x35, 0x21, 0xc8, 0xf0, 0xcb, 0xae, 0xd2,
        0xad, 0xd7, 0x2b, 0x0f, 0x9d, 0xb3, 0xc5, 0x32, 0x1a, 0x2a, 0xfe, 0x59, 0xf3, 0x5a, 0x0d, 0xac, 0x68, 0xf1,
        0xfa, 0x62, 0x1e, 0xfb, 0x2c, 0x8d, 0x0c, 0xb7, 0x39, 0x2d, 0x92, 0x47, 0xe3, 0xd7, 0x35, 0x1a, 0x6d, 0xbd,
        0x24, 0xc2, 0xae, 0x25, 0x5b, 0x88, 0xff, 0xab, 0x73, 0x29, 0x8a, 0x0b, 0xcc, 0xcd, 0x0c, 0x58, 0x67, 0x31,
        0x89, 0xe8, 0xbd, 0x34, 0x80, 0x78, 0x4a, 0x5f, 0xc9, 0x6b, 0x89, 0x9d, 0x95, 0x6b, 0xfc, 0x86, 0xd7, 0x4f,
        0x33, 0xa6, 0x78, 0x17, 0x96, 0xc9, 0xc3, 0x2d, 0x0d, 0x32, 0xa5, 0xab, 0xcd, 0x05, 0x27, 0xe2, 0xf7, 0x10,
        0xa3, 0x96, 0x13, 0xc4, 0x2f, 0x99, 0xc0, 0x27, 0xbf, 0xed, 0x04, 0x9c, 0x3c, 0x27, 0x58, 0x04, 0xb6, 0xb2,
        0x19, 0xf9, 0xc1, 0x2f, 0x02, 0xe9, 0x48, 0x63, 0xec, 0xa1, 0xb6, 0x42, 0xa0, 0x9d, 0x48, 0x25, 0xf8, 0xb3,
        0x9d, 0xd0, 0xe8, 0x6a, 0xf9, 0x48, 0x4d, 0xa1, 0xc2, 0xba, 0x86, 0x30, 0x42, 0xea, 0x9d, 0xb3, 0x08, 0x6c,
        0x19, 0x0e, 0x48, 0xb3, 0x9d, 0x66, 0xeb, 0x00, 0x06, 0xa2, 0x5a, 0xee, 0xa1, 0x1b, 0x13, 0x87, 0x3c, 0xd7,
        0x19, 0xe6, 0x55, 0xbd
};

Session::Session(const std::string &addr) {
    this->conn = utils::ConnectionHolder::create(addr);
    this->running = false;
    this->auth_lock = false;
}

void Session::connect() {
    utils::ByteArray acc;
    spotify::ClientHello client_hello;
    uint8_t nonce[16];
    uint8_t padding[] = {0x1E};
    DiffieHellman dh;

    // Send ClientHello
    RAND_bytes(nonce, sizeof(nonce));

    Version::build_info(client_hello.mutable_build_info());
    client_hello.add_cryptosuites_supported(spotify::CRYPTO_SUITE_SHANNON);
    client_hello.mutable_login_crypto_hello()->mutable_diffie_hellman()->set_gc(dh.get_public_key(),
                                                                                dh.get_public_key_length());
    client_hello.mutable_login_crypto_hello()->mutable_diffie_hellman()->set_server_keys_known(1);
    client_hello.set_client_nonce(nonce, sizeof(nonce));
    client_hello.set_padding(padding, sizeof(padding));

    auto client_hello_string = client_hello.SerializeAsString();
    int length = 1 + 1 + 4 + (int) client_hello_string.size();
    conn->write_byte(0);
    conn->write_byte(4);
    conn->write_int(length);
    conn->write(client_hello_string);

    acc.write_byte(0);
    acc.write_byte(4);
    acc.write_int(length);
    acc.write(client_hello_string);

    length = conn->read_int();
    auto buffer = conn->read_fully(length - 4);

    acc.write_int(length);
    acc.write(buffer);

    // Read APResponseMessage
    spotify::APResponseMessage ap_response_message;
    ap_response_message.ParseFromArray(buffer.data(), buffer.size());

    // Check gs_signature
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(SERVER_KEY, sizeof(SERVER_KEY), nullptr);
    BIGNUM *e = nullptr; BN_dec2bn(&e, "65537");
    RSA_set0_key(rsa, n, e, nullptr);
    EVP_PKEY *pub_key = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pub_key, rsa);
    EVP_MD_CTX *rsa_verify_ctx = EVP_MD_CTX_new();

    if (EVP_DigestVerifyInit(rsa_verify_ctx, nullptr, EVP_sha1(), nullptr, pub_key) != 1) {
        // TODO: Handle error
        std::cout << "Failed to init digest verify!" << std::endl;
    }

    auto gs = ap_response_message.challenge().login_crypto_challenge().diffie_hellman().gs();
    if (EVP_DigestVerifyUpdate(rsa_verify_ctx, gs.c_str(), gs.size()) != 1) {
        // TODO: Handle error
        std::cout << "Failed to update digest verify!" << std::endl;
    }

    auto gs_signature = ap_response_message.challenge().login_crypto_challenge().diffie_hellman().gs_signature();
    if (EVP_DigestVerifyFinal(rsa_verify_ctx, (const unsigned char *) gs_signature.c_str(), gs_signature.size()) != 1) {
        // TODO: Handle error
        std::cout << "Failed to verify digest!" << std::endl;
    }

    EVP_MD_CTX_free(rsa_verify_ctx);
    EVP_PKEY_free(pub_key);
    RSA_free(rsa);

    // Solve challenge
    utils::ByteArray data;
    auto shared_key = dh.compute_shared_key(
            ap_response_message.challenge().login_crypto_challenge().diffie_hellman().gs());
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    unsigned int tmp_len = EVP_MD_size(EVP_sha1());
    auto tmp = std::make_unique<uint8_t[]>(tmp_len);
    for (uint8_t i = 1; i < 6; i++) {
        HMAC_Init_ex(hmac_ctx, shared_key.data(), shared_key.size(), EVP_sha1(), nullptr);
        HMAC_Update(hmac_ctx, acc.data(), acc.size());
        HMAC_Update(hmac_ctx, &i, 1);
        HMAC_Final(hmac_ctx, tmp.get(), &tmp_len);
        data.write(reinterpret_cast<const char *>(tmp.get()), tmp_len);
        HMAC_CTX_reset(hmac_ctx);
    }

    HMAC_Init_ex(hmac_ctx, data.data(), 20, EVP_sha1(), nullptr);
    HMAC_Update(hmac_ctx, acc.data(), acc.size());
    HMAC_Final(hmac_ctx, tmp.get(), &tmp_len);
    HMAC_CTX_free(hmac_ctx);

    spotify::ClientResponsePlaintext client_response_plaintext;
    client_response_plaintext.mutable_login_crypto_response()->mutable_diffie_hellman()->set_hmac(tmp.get(), tmp_len);
    client_response_plaintext.mutable_pow_response();
    client_response_plaintext.mutable_crypto_response();

    auto client_response_plaintext_string = client_response_plaintext.SerializeAsString();
    length = 4 + (int) client_response_plaintext_string.size();
    conn->write_int(length);
    conn->write(client_response_plaintext_string);

    uint8_t scrap[4];
    conn->set_timeout(1);
    int read = conn->read(scrap, sizeof(scrap));
    conn->restore_timeout();
    if (read == sizeof(scrap)) {
        // TODO: Handle error
        std::cout << "Login failed!" << std::endl;
        length = (scrap[0] << 24) | (scrap[1] << 16) | (scrap[2] << 8) | (scrap[3] << 0);
        auto payload = conn->read_fully(length - 4);
        spotify::APResponseMessage ap_error_message;
        ap_error_message.ParseFromArray(payload.data(), payload.size());
        std::cout << ap_error_message.login_failed().error_description() << std::endl;
    } else if (read > 0) {
        // TODO: Handle error
        std::cout << "Got unknown data!" << std::endl;
    }

    // TODO: synchronize auth_lock
    cipher_pair = std::make_unique<CipherPair>(&data[20], 32, &data[52], 32);
    auth_lock = true;
    // TODO: end synchronize auth_lock

    std::cout << "Connected successfully!" << std::endl;
}

std::unique_ptr<Session> Session::create() {
    return std::make_unique<Session>(ApResolver::get_instance().get_accesspoint());
}

void Session::authenticate(const spotify::LoginCredentials &credentials) {
    authenticate_partial((spotify::LoginCredentials &) credentials, false);

    // TODO: synchronized (auth_lock) {
    mercury_client = std::make_unique<MercuryClient>();
    //token_provider = std::make_unique<TokenProvider>();
    audio_key_manager = std::make_unique<AudioKeyManager>();
    channel_manager = std::make_unique<ChannelManager>();
    //api = std::make_unique<ApiClient>();
    //cdn_manager = std::make_unique<CdnManager>();
    //content_feeder = std::make_unique<PlayableContentFeeder>();
    //cache_manager = std::make_unique<CacheManager>();
    //dealer = std::make_unique<DealerClient>();
    //search = std::make_unique<SearchManager>();
    //event_service = std::make_unique<EventService>();

    auth_lock = false;
    // TODO: auth_lock.notifyAll();
    // TODO: End synchronized

    //event_service.language("en");
    //TimeProvider::init();
    //dealer.connect();

    std::cout << "Authenticated as " << "nobody" << "!" << std::endl;
    //mercury().interested_in("spotify::user::attributes::update", listener?);
    //dealer().addMessageListener(listener?, "hm://connect-state/v1/connect/logout");
}

void session_packet_receiver(Session *session) {
    std::cout << "Session::session_packet_receiver started" << std::endl;

    while (session->running) {
        Packet packet = session->cipher_pair->receive_encoded(session->conn);

        if (!session->running) break;

        switch (packet.cmd) {
            case Packet::Type::Ping: {

                break;
            }
            case Packet::Type::PongAck: {
                // Silent
                break;
            }
            case Packet::Type::CountryCode: {
                std::string country_code(packet.payload.begin(), packet.payload.end());
                std::cout << "Received CountryCode: " << country_code << std::endl;
                break;
            }
            case Packet::Type::LicenseVersion: {

                break;
            }
            case Packet::Type::Unknown_0x10: {
                std::cout << "Received 0x10" << std::endl;
                break;
            }
            case Packet::Type::MercurySub:
            case Packet::Type::MercuryUnsub:
            case Packet::Type::MercuryEvent:
            case Packet::Type::MercuryReq: {
                session->mercury()->dispatch(packet);
                break;
            }
            case Packet::Type::AesKey:
            case Packet::Type::AesKeyError: {
                session->audio_key()->dispatch(packet);
                break;
            }
            case Packet::Type::ChannelError:
            case Packet::Type::StreamChunkRes: {
                session->channel()->dispatch(packet);
                break;
            }
            default: {
                std::cout << "Skipping 0x" << std::hex << packet.cmd << std::endl;
                break;
            }
        }
    }

    std::cout << "Session::session_packet_receiver stopped" << std::endl;
}

void Session::authenticate_partial(spotify::LoginCredentials &credentials, bool remove_lock) {
    if (cipher_pair == nullptr) {
        // TODO: Handle error
        std::cout << "Connection not established!" << std::endl;
    }

    spotify::ClientResponseEncrypted client_response_encrypted;
    client_response_encrypted.set_allocated_login_credentials(&credentials);
    Version::system_info(client_response_encrypted.mutable_system_info());
    client_response_encrypted.set_version_string(Version::version_string());

    auto client_response_string = client_response_encrypted.SerializeAsString();
    client_response_encrypted.release_login_credentials(); // We're not the owner of LoginCredentials
    send_unchecked(Packet::Type::Login, client_response_string);

    Packet packet = cipher_pair->receive_encoded(conn);
    if (packet.cmd == Packet::Type::APWelcome) {
        std::cout << "Authentication success!" << std::endl;
        ap_welcome.ParseFromArray(packet.payload.data(), packet.payload.size());
        receiver = std::make_unique<std::thread>(session_packet_receiver, this);

        std::vector<uint8_t> bytes0x0f(20);
        RAND_bytes(bytes0x0f.data(), bytes0x0f.size());
        send_unchecked(Packet::Type::Unknown_0x0f, bytes0x0f);

        utils::ByteArray preferred_locale;
        preferred_locale.write_byte(0x00);
        preferred_locale.write_byte(0x00);
        preferred_locale.write_byte(0x10);
        preferred_locale.write_byte(0x00);
        preferred_locale.write_byte(0x02);
        preferred_locale.write("preferred-locale");
        preferred_locale.write("en"); // TODO: Fix this with some sort of config :)
        send_unchecked(Packet::Type::PreferredLocale, preferred_locale);

        if (remove_lock) {
            // TODO: Synchronize with auth_lock
            auth_lock = false;
            // TODO: Notify all auth_lock
        }

    } else if (packet.cmd == Packet::Type::AuthFailure) {
        // TODO: Handle error
        spotify::APLoginFailed login_failed;
        login_failed.ParseFromArray(packet.payload.data(), packet.payload.size());
        std::cout << "SpotifyAuthenticationException: " << login_failed.error_code() << std::endl;
    } else {
        // TODO: Handle error
        std::cout << "Unknown CMD 0x" << std::endl;
    }
}

void Session::send_unchecked(Packet::Type cmd, std::vector<uint8_t> &payload) {
    cipher_pair->send_encoded(conn, cmd, payload);
}

void Session::send_unchecked(Packet::Type cmd, std::string &payload) {
    auto vector = std::vector<uint8_t>(payload.begin(), payload.end());
    cipher_pair->send_encoded(conn, cmd, vector);
}

const std::unique_ptr<MercuryClient> &Session::mercury() const {
    // waitAuthLock();
    if (mercury_client == nullptr) {
        // TODO: Handle error
        std::cout << "Session isn't authenticated" << std::endl;
    }
    return mercury_client;
}

const std::unique_ptr<AudioKeyManager> &Session::audio_key() const {
    // waitAuthLock();
    if (audio_key_manager == nullptr) {
        // TODO: Handle error
        std::cout << "Session isn't authenticated" << std::endl;
    }
    return audio_key_manager;
}

const std::unique_ptr<ChannelManager> &Session::channel() const {
    // waitAuthLock();
    if (channel_manager == nullptr) {
        // TODO: Handle error
        std::cout << "Session isn't authenticated" << std::endl;
    }
    return channel_manager;
}

Session::~Session() {
    running = false;
    if (receiver != nullptr) receiver->join();
}
