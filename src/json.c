//
// Created by Iscle on 26/01/2021.
//

#include <cjson/cJSON.h>
#include "json.h"

cJSON *json_get_array(char *str, char *key) {
    cJSON *json;
    cJSON *arr;

    json = cJSON_Parse(str);
    if (json == NULL)
        return NULL;

    return cJSON_GetObjectItem(json, "dealer");
}