//
// Created by Iscle on 30/01/2021.
//

#ifndef LIBRESPOT_C_VERSION_H
#define LIBRESPOT_C_VERSION_H

#include <proto/keyexchange.pb.h>

class Version {
private:
    static spotify::Platform platform();

public:
    static spotify::BuildInfo standard_build_info();
};

#endif //LIBRESPOT_C_VERSION_H
