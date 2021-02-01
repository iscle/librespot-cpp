//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_AP_RESOLVER_H
#define LIBRESPOT_C_AP_RESOLVER_H

#include <string>
#include <vector>

class ApResolver {
public:
    static ApResolver &get_instance();
    std::string &get_dealer();
    std::string &get_spclient();
    std::string &get_accesspoint();
private:
    static void populate_list(const char *params, const char *arr_name, std::vector<std::string> &list);
    std::vector<std::string> dealer_list;
    std::vector<std::string> spclient_list;
    std::vector<std::string> accesspoint_list;
};

#endif //LIBRESPOT_C_AP_RESOLVER_H
