//
// Created by Iscle on 01/02/2021.
//

#ifndef LIBRESPOT_C_AUDIO_KEY_MANAGER_H
#define LIBRESPOT_C_AUDIO_KEY_MANAGER_H


#include "../crypto/packet.h"

class AudioKeyManager {
public:
    void dispatch(Packet &packet);
};


#endif //LIBRESPOT_C_AUDIO_KEY_MANAGER_H
