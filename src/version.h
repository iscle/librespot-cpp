//
// Created by Iscle on 30/01/2021.
//

#ifndef LIBRESPOT_C_VERSION_H
#define LIBRESPOT_C_VERSION_H

#include <proto/keyexchange.pb.h>
#include <proto/authentication.pb.h>

class Version {
private:
    static spotify::Platform platform();

public:
    static spotify::BuildInfo * build_info();

    static spotify::SystemInfo system_info();

    static std::string version_string();
};

#endif //LIBRESPOT_C_VERSION_H
