//
// Created by Iscle on 26/01/2021.
//

#include "ap_resolver.h"
#include <vector>
#include <string>
#include <rapidjson/rapidjson.h>
#include <random>
#include <rapidjson/document.h>
#include "network/http.h"

#define BASE_URL "http://apresolve.spotify.com"
#define DEALERS_URL "?type=dealer"
#define SPCLIENTS_URL "?type=spclient"
#define ACCESSPOINTS_URL "?type=accesspoint"

static std::vector<std::string> dealer_list;
static std::vector<std::string> spclient_list;
static std::vector<std::string> accesspoint_list;

static void populate_list(const char *params, const char *arr_name, std::vector<std::string> &list) {
    rapidjson::Document json;

    std::string res = http_get(BASE_URL, params);
    json.Parse(res.c_str());

    auto arr = json[arr_name].GetArray();

    for (auto &&i : arr)
        list.emplace_back(i.GetString());
}

std::string &ap_resolver_get_dealer() {
    if (dealer_list.empty())
        populate_list(DEALERS_URL, "dealer", dealer_list);

    return dealer_list[rand() % dealer_list.size()];
}

std::string &ap_resolver_get_spclient() {
    if (spclient_list.empty())
        populate_list(SPCLIENTS_URL, "spclient", spclient_list);

    return spclient_list[rand() % spclient_list.size()];
}

std::string &ap_resolver_get_accesspoint() {
    if (accesspoint_list.empty())
        populate_list(ACCESSPOINTS_URL, "accesspoint", accesspoint_list);

    return accesspoint_list[rand() % accesspoint_list.size()];
}
