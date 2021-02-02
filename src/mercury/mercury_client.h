//
// Created by Iscle on 01/02/2021.
//

#ifndef LIBRESPOT_C_MERCURY_CLIENT_H
#define LIBRESPOT_C_MERCURY_CLIENT_H


#include <list>
#include "../crypto/packet.h"
#include "raw_mercury_request.h"

class MercuryClient {
public:
    class Response {
    public:
        std::string uri;
        std::vector<std::vector<uint8_t>> payload;
        int status_code;
    };

    class SubListener {
    public:
        virtual void event(MercuryClient::Response &resp) {
            throw std::runtime_error("Stub!");
        };
    };

    class InternalSubListener {
    public:
        InternalSubListener(const std::string &uri, SubListener listener, bool is_sub);

        bool matches(std::string &uri);

    private:
        std::string uri;
        SubListener listener;
        bool is_sub;
    };

    class Callback {
        virtual void response(Response &response) {
            throw std::runtime_error("Stub!");
        };
    };

    class SyncCallback : public Callback {
        void response(Response &response) override;

    public:
        Response waitResponse();
    };

    void subscribe(std::string &uri, SubListener &listener);
    void unsubscribe(std::string &uri);
    Response send_sync(RawMercuryRequest &request);
    int send(RawMercuryRequest &request, Callback &callback);
    void dispatch(Packet &packet);
    void interested_in(std::string &uri, SubListener &listener);
    void not_interested(SubListener &listener);

private:
    std::list<InternalSubListener> subscriptions;
};


#endif //LIBRESPOT_C_MERCURY_CLIENT_H
