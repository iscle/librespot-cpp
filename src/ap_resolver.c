//
// Created by Iscle on 26/01/2021.
//

#include "ap_resolver.h"
#include "data/list.h"
#include <stdlib.h>
#include <stdio.h>
#include "network/http.h"
#include <cjson/cJSON.h>
#include <string.h>
#include <time.h>

#define BASE_URL "http://apresolve.spotify.com"
#define DEALERS_URL BASE_URL "?type=dealer"
#define SPCLIENTS_URL BASE_URL "?type=spclient"
#define ACCESSPOINTS_URL BASE_URL "?type=accesspoint"

static list_t *dealer_list = NULL;
static list_t *spclient_list = NULL;
static list_t *accesspoint_list = NULL;

static int populate_list(char *url, char *arr_name, list_t **list) {
    char *data = NULL;
    int ret;
    cJSON *json;
    cJSON *arr;
    cJSON *i;

    ret = http_get(url, &data);
    if (ret < 0)
        return ret;

    ret = -1;

    json = cJSON_Parse(data);
    free(data);
    if (json == NULL)
        return ret;

    arr = cJSON_GetObjectItem(json, arr_name);
    if (arr == NULL)
        goto exit;

    *list = list_create();
    cJSON_ArrayForEach(i, arr) {
        char *item = cJSON_GetStringValue(i);
        size_t item_length = strlen(item);
        char *ptr = malloc(item_length + 1);
        if (ptr == NULL)
            goto exit;
        memcpy(ptr, item, item_length + 1);
        if (list_add(*list, ptr) < 0) {
            free(ptr);
            goto exit;
        }
    }

    ret = 0;

    exit:
    cJSON_Delete(json);
    return ret;
}

char *ap_resolver_get_dealer(void) {
    if (dealer_list == NULL)
        if (populate_list(DEALERS_URL, "dealer", &dealer_list) < 0)
            return NULL;

    if (list_size(dealer_list) == 0) return NULL;

    return list_get(dealer_list, rand() % list_size(dealer_list));
}

char *ap_resolver_get_spclient(void) {
    if (spclient_list == NULL)
        if (populate_list(SPCLIENTS_URL, "spclient", &spclient_list) < 0)
            return NULL;

    if (list_size(spclient_list) == 0) return NULL;

    return list_get(spclient_list, rand() % list_size(spclient_list));
}

char *ap_resolver_get_accesspoint(void) {
    if (accesspoint_list == NULL)
        if (populate_list(ACCESSPOINTS_URL, "accesspoint", &accesspoint_list) < 0)
            return NULL;

    if (list_size(accesspoint_list) == 0) return NULL;

    return list_get(accesspoint_list, rand() % list_size(accesspoint_list));
}

void ap_resolver_destroy(void) {
    int i;
    int list_sz;

    if (dealer_list != NULL) {
        list_sz = list_size(dealer_list);
        for (i = 0; i < list_sz; i++)
            free(list_get(dealer_list, i));
        list_destroy(dealer_list);
        dealer_list = NULL;
    }

    if (spclient_list != NULL) {
        list_sz = list_size(spclient_list);
        for (i = 0; i < list_sz; i++)
            free(list_get(spclient_list, i));
        list_destroy(spclient_list);
        spclient_list = NULL;
    }

    if (accesspoint_list != NULL) {
        list_sz = list_size(accesspoint_list);
        for (i = 0; i < list_sz; i++)
            free(list_get(accesspoint_list, i));
        list_destroy(accesspoint_list);
        accesspoint_list = NULL;
    }
}