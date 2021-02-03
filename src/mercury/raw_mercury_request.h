//
// Created by Iscle on 02/02/2021.
//

#ifndef LIBRESPOT_CPP_RAW_MERCURY_REQUEST_H
#define LIBRESPOT_CPP_RAW_MERCURY_REQUEST_H


#include <string>
#include <proto/mercury.pb.h>

class RawMercuryRequest {
public:
    spotify::Header header;
    std::vector<std::vector<uint8_t>> payload;

    static RawMercuryRequest sub(std::string &uri);

    static RawMercuryRequest unsub(std::string &uri);
};


#endif //LIBRESPOT_CPP_RAW_MERCURY_REQUEST_H
