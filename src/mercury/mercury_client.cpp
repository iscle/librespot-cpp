//
// Created by Iscle on 01/02/2021.
//

#include <iostream>
#include <proto/pubsub.pb.h>
#include "mercury_client.h"

void MercuryClient::subscribe(std::string &uri, SubListener &listener) {
    RawMercuryRequest request = RawMercuryRequest::sub(uri);
    Response response = send_sync(request);
    if (response.status_code != 200) {
        // TODO: Handle error
        std::cout << "status_code != 200!" << std::endl;
    }

    if (!response.payload.empty()) {
        for (std::vector<uint8_t> &payload : response.payload) {
            spotify::Subscription sub;
            sub.ParseFromArray(payload.data(), payload.size());
            subscriptions.emplace_back(sub.uri(), listener, true);
        }
    } else {
        subscriptions.emplace_back(uri, listener, true);
    }

    std::cout << "Subscribed successfully to " << uri << "!" << std::endl;
}

void MercuryClient::unsubscribe(std::string &uri) {
    RawMercuryRequest request = RawMercuryRequest::unsub(uri);
    Response response = send_sync(request);
    if (response.status_code != 200) {
        // TODO: Handle error
        std::cout << "status_code != 200!" << std::endl;
    }

    subscriptions.remove_if([&uri](InternalSubListener &l) {
        return l.matches(uri);
    });

    std::cout << "Unsubscribed successfully from " << uri << "!" << std::endl;
}

MercuryClient::Response MercuryClient::send_sync(RawMercuryRequest &request) {
    SyncCallback callback;
    int seq = send(request, callback);

    // TODO: Try catch
    return callback.waitResponse();
}

int MercuryClient::send(RawMercuryRequest &request, MercuryClient::Callback &callback) {
    return 0;
}

void MercuryClient::dispatch(Packet &packet) {

}

void MercuryClient::interested_in(std::string &uri, SubListener &listener) {

}

void MercuryClient::not_interested(SubListener &listener) {

}

MercuryClient::InternalSubListener::InternalSubListener(const std::string &uri, MercuryClient::SubListener listener,
                                                        bool is_sub) {

}

bool MercuryClient::InternalSubListener::matches(std::string &uri) {
    return this->uri.rfind(uri, 0) == 0;
}

void MercuryClient::SyncCallback::response(Response &response) {

}

MercuryClient::Response MercuryClient::SyncCallback::waitResponse() {
    return MercuryClient::Response();
}
