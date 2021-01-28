//
// Created by Iscle on 27/01/2021.
//

#ifndef LIBRESPOT_C_BASE62_H
#define LIBRESPOT_C_BASE62_H

#include <stdint.h>
#include <stddef.h>

uint8_t *base62_decode(const char *data, size_t data_size, size_t target_size);

char *base62_encode(const uint8_t *data, size_t data_size, size_t target_size);

#endif //LIBRESPOT_C_BASE62_H
