//
// Created by Iscle on 26/01/2021.
//

#include "list.h"

list_t *list_create(void) {
    list_t *list = malloc(sizeof(list_t));
    if (list == NULL)
        return NULL;
    list->size = 0;
    list->elements = NULL;
    return list;
}

// Returns the new item position, or -1 on error
ssize_t list_add(list_t *list, void *element) {
    void **tmp = realloc(list->elements, sizeof(*list->elements) * (list->size + 1));
    if (tmp == NULL)
        return -1;

    list->elements = tmp;
    list->elements[list->size] = element;
    return list->size++;
}

void *list_get(list_t *list, size_t element) {
    if (element < 0 || element >= list->size)
        return NULL;

    return list->elements[element];
}

size_t list_size(list_t *list) {
    return list->size;
}

void list_destroy(list_t *list) {
    free(list->elements);
    free(list);
}