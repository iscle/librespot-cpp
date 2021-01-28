//
// Created by Iscle on 26/01/2021.
//

#include "http.h"
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

struct http_response {
    char *response;
    size_t size;
};

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct http_response *mem = (struct http_response *) userdata;

    char *tmp = realloc(mem->response, mem->size + realsize + 1);
    if (tmp == NULL)
        return 0;

    mem->response = tmp;
    memcpy(&(mem->response[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->response[mem->size] = '\0';

    return realsize;
}

int http_get(char *url, char **buf) {
    CURL *curl;
    struct http_response mem = {0};
    long status;

    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "librespot-c/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mem);

    //curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status); // TODO: FIXME

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    *buf = mem.response;

    return 0;
}