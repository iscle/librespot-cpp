//
// Created by Iscle on 31/01/2021.
//

#ifndef LIBRESPOT_C_PACKET_H
#define LIBRESPOT_C_PACKET_H


#include <stdint-gcc.h>
#include <cstddef>

class Packet {
public:
    enum Type {
        SecretBlock = 0x02,
        Ping = 0x04,
        StreamChunk = 0x08,
        StreamChunkRes = 0x09,
        ChannelError = 0x0a,
        ChannelAbort = 0x0b,
        RequestKey = 0x0c,
        AesKey = 0x0d,
        AesKeyError = 0x0e,
        Image = 0x19,
        CountryCode = 0x1b,
        Pong = 0x49,
        PongAck = 0x4a,
        Pause = 0x4b,
        ProductInfo = 0x50,
        LegacyWelcome = 0x69,
        LicenseVersion = 0x76,
        Login = 0xab,
        APWelcome = 0xac,
        AuthFailure = 0xad,
        MercuryReq = 0xb2,
        MercurySub = 0xb3,
        MercuryUnsub = 0xb4,
        MercuryEvent = 0xb5,
        TrackEndedTime = 0x82,
        UnknownData_AllZeros = 0x1f,
        PreferredLocale = 0x74,
        Unknown_0x4f = 0x4f,
        Unknown_0x0f = 0x0f,
        Unknown_0x10 = 0x10,
    };

    uint8_t cmd;
    uint8_t *payload;
    size_t payload_size;
    Packet(uint8_t cmd, uint8_t *payload, size_t payload_size);
    bool is(Type type) const;
};


#endif //LIBRESPOT_C_PACKET_H
