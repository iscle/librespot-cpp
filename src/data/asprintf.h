//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_ASPRINTF_H
#define LIBRESPOT_C_ASPRINTF_H

#include <stdarg.h>

int asprintf(char **strp, const char *fmt, ...);

int vasprintf(char **strp, const char *fmt, va_list ap);

#endif //LIBRESPOT_C_ASPRINTF_H
