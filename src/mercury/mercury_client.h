//
// Created by Iscle on 01/02/2021.
//

#ifndef LIBRESPOT_C_MERCURY_CLIENT_H
#define LIBRESPOT_C_MERCURY_CLIENT_H


#include "../crypto/packet.h"

class MercuryClient {
public:
    void dispatch(Packet &packet);
};


#endif //LIBRESPOT_C_MERCURY_CLIENT_H
