//
// Created by Iscle on 26/01/2021.
//

#include <stdio.h>
#include <stdlib.h>
#include "asprintf.h"

int asprintf(char **strp, const char *fmt, ...) {
    int size = 0;
    va_list args;

    // init variadic argumens
    va_start(args, fmt);

    // format and get size
    size = vasprintf(strp, fmt, args);

    // toss args
    va_end(args);

    return size;
}

int vasprintf(char **strp, const char *fmt, va_list ap) {
    int size;
    va_list tmp_ap;

    va_copy(tmp_ap, ap);
    size = vsnprintf(NULL, 0, fmt, tmp_ap); // Calculate the resulting length
    va_end(tmp_ap);

    if (size < 0)
        return -1;

    *strp = malloc(size + 1); // +1 for the NULL terminator
    if (*strp == NULL)
        return -1;

    size = vsprintf(*strp, fmt, ap);
    if (size < 0) {
        free(*strp);
        *strp = NULL;
        return -1;
    }

    return size;
}