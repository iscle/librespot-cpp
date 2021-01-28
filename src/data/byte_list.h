//
// Created by Iscle on 28/01/2021.
//

#ifndef LIBRESPOT_C_BYTE_LIST_H
#define LIBRESPOT_C_BYTE_LIST_H

#include <sys/types.h>
#include <stdint.h>

typedef struct {
    size_t size;
    uint8_t *elements;
} byte_list_t;

byte_list_t *byte_list_create(void);

ssize_t byte_list_add(byte_list_t *list, uint8_t element);

uint8_t byte_list_get(byte_list_t *list, size_t element);

size_t byte_list_size(byte_list_t *list);

byte_list_t *byte_list_reverse(byte_list_t *list);

int byte_list_truncate(byte_list_t *list, size_t size);

void byte_list_destroy(byte_list_t *list);

#endif //LIBRESPOT_C_BYTE_LIST_H
