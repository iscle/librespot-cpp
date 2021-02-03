//
// Created by Iscle on 01/02/2021.
//

#ifndef LIBRESPOT_C_MERCURY_CLIENT_H
#define LIBRESPOT_C_MERCURY_CLIENT_H


#include <list>
#include "../crypto/packet.h"
#include "raw_mercury_request.h"
//#include "../core/session.h"

class MercuryResponse {
public:
    std::string uri;
    std::shared_ptr<std::vector<std::vector<uint8_t>>> payload;
    int status_code;

    MercuryResponse(spotify::Header &header, std::shared_ptr<std::vector<std::vector<uint8_t>>> payload);
};

class SubListener { ;
public:
    virtual void event(MercuryResponse &response) {
        throw std::runtime_error("Stub!");
    }
};

class MercuryClient : public SubListener {
public:
    class InternalSubListener {
    public:
        SubListener *listener;

        InternalSubListener(std::string uri, SubListener *listener, bool is_sub);

        bool matches(const std::string &uri);

        void dispatch(MercuryResponse &resp) const;

    private:
        std::string uri;
        bool is_sub;
    };

    class Callback {
        virtual void response(MercuryResponse &response) {
            throw std::runtime_error("Stub!");
        };
    };

    class SyncCallback : public Callback {
        void response(MercuryResponse &response) override;

    public:
        MercuryResponse waitResponse();
    };

    void subscribe(std::string &uri, SubListener *listener);

    void unsubscribe(std::string &uri);

    MercuryResponse send_sync(RawMercuryRequest &request);

    int send(RawMercuryRequest &request, Callback *callback);

    void dispatch(Packet &packet);

    void interested_in(std::string &uri, SubListener *listener);

    void not_interested(SubListener *listener);

private:
    static constexpr int MERCURY_REQUEST_TIMEOUT = 3000;
    std::atomic<int> seq_holder;
    std::map<long, Callback *> callbacks;
    std::list<InternalSubListener> subscriptions;
    std::map<long, std::shared_ptr<std::vector<std::vector<uint8_t>>>> partials;
    //Session *session;

    void event(MercuryResponse &resp);
};


#endif //LIBRESPOT_C_MERCURY_CLIENT_H
