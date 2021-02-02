//
// Created by Iscle on 26/01/2021.
//

#include "ap_resolver.h"
#include <vector>
#include <string>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include "../network/http.h"

#define BASE_URL "http://apresolve.spotify.com"
#define DEALERS_URL "?type=dealer"
#define SPCLIENTS_URL "?type=spclient"
#define ACCESSPOINTS_URL "?type=accesspoint"

ApResolver &ApResolver::get_instance() {
    static ApResolver instance;
    return instance;
}

void ApResolver::populate_list(const char *params, const char *arr_name, std::vector<std::string> &list) {
    std::string res = http_get(BASE_URL, params);
    rapidjson::Document json;
    json.Parse(res.c_str());
    for (auto &&i : json[arr_name].GetArray())
        list.emplace_back(i.GetString());
}

std::string &ApResolver::get_dealer() {
    if (dealer_list.empty())
        populate_list(DEALERS_URL, "dealer", dealer_list);

    return dealer_list[rand() % dealer_list.size()];
}

std::string &ApResolver::get_spclient() {
    if (spclient_list.empty())
        populate_list(SPCLIENTS_URL, "spclient", spclient_list);

    return spclient_list[rand() % spclient_list.size()];
}

std::string &ApResolver::get_accesspoint() {
    if (accesspoint_list.empty())
        populate_list(ACCESSPOINTS_URL, "accesspoint", accesspoint_list);

    return accesspoint_list[rand() % accesspoint_list.size()];
}
