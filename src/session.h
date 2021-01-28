//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_SESSION_H
#define LIBRESPOT_C_SESSION_H

struct StoredToken {
    int expires_in;
    char *accessToken;
    char **scopes;
    unsigned long timestamp;
};

#endif //LIBRESPOT_C_SESSION_H
