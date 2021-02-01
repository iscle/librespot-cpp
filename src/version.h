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
    static void build_info(spotify::BuildInfo *build_info);

    static std::string version_string();

    static void system_info(spotify::SystemInfo *system_info);
};

#endif //LIBRESPOT_C_VERSION_H
