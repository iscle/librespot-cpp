//
// Created by Iscle on 02/02/2021.
//

#ifndef LIBRESPOT_CPP_RAW_MERCURY_REQUEST_H
#define LIBRESPOT_CPP_RAW_MERCURY_REQUEST_H


#include <string>

class RawMercuryRequest {

public:
    static RawMercuryRequest sub(std::string &uri);

    static RawMercuryRequest unsub(std::string &uri);
};


#endif //LIBRESPOT_CPP_RAW_MERCURY_REQUEST_H
