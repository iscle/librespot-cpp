//
// Created by Iscle on 28/01/2021.
//

#include <malloc.h>
#include "byte_list.h"

byte_list_t *byte_list_create(void) {
    byte_list_t *list = malloc(sizeof(byte_list_t));
    if (list == NULL)
        return NULL;

    list->size = 0;
    list->elements = NULL;
    return list;
}

ssize_t byte_list_add(byte_list_t *list, uint8_t element) {
    uint8_t *tmp = realloc(list->elements, sizeof(*list->elements) * (list->size + 1));
    if (tmp == NULL)
        return -1;

    list->elements = tmp;
    list->elements[list->size] = element;
    return list->size++;
}

uint8_t byte_list_get(byte_list_t *list, size_t element) {
    if (element < 0 || element >= list->size)
        return 0;

    return list->elements[element];
}

size_t byte_list_size(byte_list_t *list) {
    return list->size;
}

byte_list_t *byte_list_reverse(byte_list_t *list) {
    size_t i;
    byte_list_t *reversed_list = byte_list_create();
    if (reversed_list == NULL)
        return NULL;
    reversed_list->elements = malloc(sizeof(*reversed_list->elements) * list->size);
    if (reversed_list->elements == NULL) {
        byte_list_destroy(reversed_list);
        return NULL;
    }

    reversed_list->size = list->size;
    for (i = 0; i < list->size; i++) {
        reversed_list->elements[reversed_list->size - i - 1] = list->elements[i];
    }

    return reversed_list;
}

int byte_list_truncate(byte_list_t *list, size_t size) {
    uint8_t *tmp;

    if (list->size <= size)
        return 0;

    tmp = realloc(list->elements, sizeof(*list->elements) * size);
    if (tmp == NULL)
        return -1;

    list->elements = tmp;
    list->size = size;
    return 0;
}

void byte_list_destroy(byte_list_t *list) {
    free(list->elements);
    free(list);
}