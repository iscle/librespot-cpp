//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_LIST_H
#define LIBRESPOT_C_LIST_H

#include <sys/types.h>
#include <stdlib.h>

typedef struct {
    size_t size;
    void **elements;
} list_t;

list_t *list_create(void);

ssize_t list_add(list_t *list, void *element);

void *list_get(list_t *list, size_t element);

size_t list_size(list_t *list);

void list_destroy(list_t *list);

#endif // LIBRESPOT_C_LIST_H
