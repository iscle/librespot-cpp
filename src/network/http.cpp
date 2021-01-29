//
// Created by Iscle on 26/01/2021.
//

#include <cpp-httplib/httplib.h>

std::string http_get(const char *url, const char* params) {
    httplib::Client cli(url);
    httplib::Headers headers = {
            { "User-Agent", "librespot-c++/1.0" }
    };
    auto res = cli.Get(params, headers);
    if (res->status != 200)
        throw "Failed to get data!";

    return res->body;
}