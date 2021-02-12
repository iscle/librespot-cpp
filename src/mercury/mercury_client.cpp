//
// Created by Iscle on 01/02/2021.
//

#include <iostream>
#include <utility>
#include <proto/pubsub.pb.h>
#include <proto/mercury.pb.h>
#include <spdlog/spdlog.h>
#include <netdb.h>
#include "mercury_client.h"
#include "../utils.h"
#include "../utils/byte_array.h"

static std::map<std::string, Packet::Type> METHOD_TYPE = {
        {"SUB",   Packet::Type::MercurySub},
        {"UNSUB", Packet::Type::MercuryUnsub},
};

MercuryClient::MercuryClient() {

}

void MercuryClient::subscribe(std::string &uri, SubListener *listener) {
    RawMercuryRequest request = RawMercuryRequest::sub(uri);
    MercuryResponse response = send_sync(request);
    if (response.status_code != 200) throw std::runtime_error("Status code != 200");

    if (!response.payload->empty()) {
        for (std::vector<uint8_t> &payload : *response.payload) {
            spotify::Subscription sub;
            sub.ParseFromArray(payload.data(), payload.size());
            subscriptions.emplace_back(sub.uri(), listener, true);
        }
    } else {
        subscriptions.emplace_back(uri, listener, true);
    }

    SPDLOG_TRACE("Subscribed successfully to {}!", uri);
}

void MercuryClient::unsubscribe(std::string &uri) {
    RawMercuryRequest request = RawMercuryRequest::unsub(uri);
    MercuryResponse response = send_sync(request);
    if (response.status_code != 200) throw std::runtime_error("Status code != 200!");

    subscriptions.remove_if([&uri](InternalSubListener &l) {
        return l.matches(uri);
    });

    SPDLOG_TRACE("Unsubscribed successfully from {}!", uri);
}

MercuryResponse MercuryClient::send_sync(RawMercuryRequest &request) {
    SyncCallback callback;
    int seq = send(request, &callback);

    // TODO: Try catch
    return callback.waitResponse();
}

/*
    @NotNull
    public <W extends JsonWrapper> W sendSync(@NotNull JsonMercuryRequest<W> request) throws IOException, MercuryException {
        Response resp = sendSync(request.request);
        if (resp.statusCode >= 200 && resp.statusCode < 300) return request.instantiate(resp);
        else throw new MercuryException(resp);
    }

    @NotNull
    public <P extends Message> ProtoWrapperResponse<P> sendSync(@NotNull ProtobufMercuryRequest<P> request) throws IOException, MercuryException {
        Response resp = sendSync(request.request);
        if (resp.statusCode >= 200 && resp.statusCode < 300)
            return new ProtoWrapperResponse<>(request.parser.parseFrom(resp.payload.stream()));
        else
            throw new MercuryException(resp);
    }

    public <W extends JsonWrapper> void send(@NotNull JsonMercuryRequest<W> request, @NotNull JsonCallback<W> callback) {
        try {
            send(request.request, resp -> {
                if (resp.statusCode >= 200 && resp.statusCode < 300) callback.response(request.instantiate(resp));
                else callback.exception(new MercuryException(resp));
            });
        } catch (IOException ex) {
            callback.exception(ex);
        }
    }

    public <P extends Message> void send(@NotNull ProtobufMercuryRequest<P> request, @NotNull ProtoCallback<P> callback) {
        try {
            send(request.request, resp -> {
                if (resp.statusCode >= 200 && resp.statusCode < 300) {
                    try {
                        callback.response(new ProtoWrapperResponse<>(request.parser.parseFrom(resp.payload.stream())));
                    } catch (InvalidProtocolBufferException ex) {
                        callback.exception(ex);
                    }
                } else {
                    callback.exception(new MercuryException(resp));
                }
            });
        } catch (IOException ex) {
            callback.exception(ex);
        }
    }
 */

int MercuryClient::send(RawMercuryRequest &request, MercuryClient::Callback *callback) {
    ByteArray out;

    int seq;
    // TODO: synchronized (seqHolder) {
    seq = seq_holder;
    seq_holder++;
    // TODO: }

    SPDLOG_TRACE("Send Mercury request, seq: {}, uri: {}, method: {}", seq, request.header.uri(),
                 request.header.method());

    out.write_short(htons(4)); // Sequence size
    out.write_int(htonl(seq)); // Sequence id
    out.write(1); // Flags
    out.write_short(htons(1 + request.payload.size())); // Parts count

    auto header = request.header.SerializeAsString();
    out.write_short(htons(header.size())); // Header size
    out.write(header); // Header

    for (const auto &part : request.payload) { // Parts
        out.write_short(htons(part.size()));
        out.write(part);
    }

    Packet::Type cmd = (METHOD_TYPE.find(request.header.method()) == METHOD_TYPE.end()) ? Packet::Type::MercuryReq
                                                                                        : METHOD_TYPE[request.header.method()];
    //session->send(cmd, out);

    callbacks.insert(std::make_pair(seq, callback));
    return seq;
}

void MercuryClient::dispatch(Packet &packet) {
    ByteBuffer payload(packet.payload);

    int seq_length = ntohs(payload.get_short());
    unsigned long seq;
    if (seq_length == 2) seq = ntohs(payload.get_short());
    else if (seq_length == 4) seq = ntohl(payload.get_int());
    else if (seq_length == 8) seq = ntohll(payload.get_long());
    else throw std::runtime_error("Unknown seq length: " + std::to_string(seq_length));

    uint8_t flags = payload.get();
    short parts = ntohs(payload.get_short());

    std::shared_ptr<std::vector<std::vector<uint8_t>>> partial;
    if (partials.find(seq) == partials.end() || flags == 0) {
        partial = std::make_shared<std::vector<std::vector<uint8_t>>>();
        partials.insert(std::make_pair(seq, partial));
    } else {
        partial = partials[seq];
    }

    SPDLOG_DEBUG("Handling packet, cmd: {}, seq: {}, flags: {}, parts: {}", packet.cmd, seq, flags, parts);

    for (int i = 0; i < parts; i++) {
        short size = ntohs(payload.get_short());
        auto buffer = payload.get(size);
        partial->emplace_back(buffer);
    }

    if (flags != 1) return;

    partials.erase(seq);

    spotify::Header header;
    header.ParseFromArray(partial->front().data(), partial->front().size());
    MercuryResponse resp(header, std::move(partial));
    if (packet.cmd == Packet::Type::MercuryEvent) {
        bool dispatched = false;
        //synchronized (subscriptions) {
        for (InternalSubListener &sub : subscriptions) {
            if (sub.matches(resp.uri)) {
                sub.dispatch(resp);
                dispatched = true;
            }
        }
        //}

        if (!dispatched)
            SPDLOG_DEBUG("Couldn't dispatch Mercury event {{seq: {}, uri: {}, code: {}}}", seq, header.uri(),
                         header.status_code());
    } else if (packet.cmd == Packet::Type::MercuryReq || packet.cmd == Packet::Type::MercurySub ||
               packet.cmd == Packet::Type::MercuryUnsub) {

    } else {
        SPDLOG_WARN("Couldn't handle packet, seq: {}, uri: {}, code: {}", seq, header.uri(), header.status_code());
    }
}

void MercuryClient::interested_in(const std::string &uri, SubListener *listener) {
    subscriptions.emplace_back(uri, listener, false);
}

void MercuryClient::not_interested(SubListener *listener) {
    subscriptions.remove_if([&listener](InternalSubListener &l) {
        return l.listener == listener;
    });
}

void MercuryClient::event(MercuryResponse &resp) {

}

MercuryClient::InternalSubListener::InternalSubListener(std::string uri, SubListener *listener, bool is_sub) :
        uri(std::move(uri)), listener(listener), is_sub(is_sub) {

}

bool MercuryClient::InternalSubListener::matches(const std::string &uri) {
    return this->uri.rfind(uri, 0) == 0;
}

void MercuryClient::InternalSubListener::dispatch(MercuryResponse &resp) const {
    listener->event(resp);
}

void MercuryClient::SyncCallback::response(MercuryResponse &response) {

}

MercuryResponse MercuryClient::SyncCallback::waitResponse() {
    throw std::runtime_error("Unimplemented!");
}

MercuryResponse::MercuryResponse(spotify::Header &header, std::shared_ptr<std::vector<std::vector<uint8_t>>> payload) :
        uri(header.uri()), status_code(header.status_code()), payload(std::move(payload)) {
    this->payload->erase(this->payload->begin()); // Remove first element
}
