//
// Created by Iscle on 27/01/2021.
//

#include "base62.h"
#include "byte_list.h"
#include <malloc.h>
#include <memory.h>

static const char ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static uint8_t *convert(const uint8_t *data, size_t data_size, int from, int to, size_t target_size) {
    uint8_t *source = (uint8_t *) data;
    size_t source_length = data_size;
    int first_run = 1;
    size_t i;
    byte_list_t *out = byte_list_create();
    if (out == NULL)
        return NULL;

    while (source_length > 0) {
        int remainder = 0;
        byte_list_t *quotient = byte_list_create();
        if (quotient == NULL) {
            byte_list_destroy(out);
            return NULL;
        }

        for (i = 0; i < source_length; i++) {
            int accumulator = source[i] + remainder * from;
            remainder = accumulator % to;
            int digit = (accumulator - remainder) / to;
            if (quotient->size > 0 || digit > 0) {
                if (byte_list_add(quotient, digit) < 0) {
                    byte_list_destroy(quotient);
                    byte_list_destroy(out);
                    return NULL;
                }
            }
        }

        byte_list_add(out, remainder);
        if (!first_run) free(source);
        source_length = quotient->size;
        if (source_length != 0) {
            source = malloc(source_length);
            if (source == NULL) {
                byte_list_destroy(quotient);
                byte_list_destroy(out);
                return NULL;
            }
            memcpy(source, quotient->elements, source_length);
            first_run = 0;
        }
        byte_list_destroy(quotient);
    }

    if (out->size < target_size) {
        size_t size = out->size;

        for (i = 0; i < target_size - size; i++)
            byte_list_add(out, 0);
    } else if (out->size > target_size) {
        byte_list_truncate(out, target_size);
    }

    byte_list_t *reversed = byte_list_reverse(out);
    byte_list_destroy(out);
    uint8_t *target = reversed->elements;
    free(reversed);
    return target;
}

static uint8_t *translate_decode(const uint8_t *data, size_t data_size) {
    size_t i;
    size_t j;
    uint8_t *translation = malloc(data_size);
    if (translation == NULL)
        return NULL;

    for (i = 0; i < data_size; i++) {
        if ((data[i] < '0' || data[i] > '9') &&
            (data[i] < 'a' || data[i] > 'z') &&
            (data[i] < 'A' || data[i] > 'Z')) {
            free(translation);
            return NULL;
        }

        for (j = 0; j < sizeof(ALPHABET); j++) {
            if (data[i] == ALPHABET[j]) {
                translation[i] = j;
                break;
            }
        }
    }

    return translation;
}

uint8_t *base62_decode(const char *data, size_t data_size, size_t target_size) {
    uint8_t *prepared = translate_decode((uint8_t *) data, data_size);
    uint8_t *converted = convert(prepared, data_size, 62, 256, target_size);
    free(prepared);
    return converted;
}

static void translate_encode(uint8_t *data, size_t data_size) {
    size_t i;

    for (i = 0; i < data_size; i++) {
        data[i] = ALPHABET[data[i]];
    }
}

char *base62_encode(const uint8_t *data, size_t data_size, size_t target_size) {
    uint8_t *indices = convert(data, data_size, 256, 62, target_size);
    translate_encode(indices, target_size);
    return (char *) indices;
}