//
// Created by Iscle on 01/02/2021.
//

#ifndef LIBRESPOT_C_CHANNEL_MANAGER_H
#define LIBRESPOT_C_CHANNEL_MANAGER_H


#include "../../crypto/packet.h"

class ChannelManager {
public:
    void dispatch(Packet &packet);
};


#endif //LIBRESPOT_C_CHANNEL_MANAGER_H
