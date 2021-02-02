//
// Created by Iscle on 27/01/2021.
//

#include "base62.h"
#include <cstring>
#include <vector>
#include <algorithm>
#include <array>

static const char ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

std::vector<uint8_t> Base62::convert(const std::vector<uint8_t> &data, int from, int to, size_t target_size) {
    size_t i;
    std::vector<uint8_t> source = data;
    std::vector<uint8_t> out;
    out.reserve(target_size);

    while (!source.empty()) {
        int remainder = 0;
        std::vector<uint8_t> quotient;
        quotient.reserve(source.size());

        for (i = 0; i < source.size(); i++) {
            int accumulator = source[i] + remainder * from;
            remainder = accumulator % to;
            int digit = (accumulator - remainder) / to;
            if (!quotient.empty() || digit > 0)
                quotient.push_back(digit);
        }

        out.push_back(remainder);
        source = quotient;
    }

    if (out.size() < target_size) {
        size_t size = out.size();
        for (i = 0; i < target_size - size; i++)
            out.push_back(0);
    } else if (out.size() > target_size) {
        out.resize(target_size);
    }

    std::reverse(out.begin(), out.end());

    return out;
}

std::vector<uint8_t> Base62::translate_decode(const std::vector<uint8_t> &data) {
    size_t i;
    size_t j;
    std::vector<uint8_t> translation;
    translation.reserve(data.size());

    for (i = 0; i < data.size(); i++) {
        if ((data[i] < '0' || data[i] > '9') &&
            (data[i] < 'a' || data[i] > 'z') &&
            (data[i] < 'A' || data[i] > 'Z')) {
            throw std::invalid_argument("Invalid Base62 character!");
        }

        for (j = 0; j < sizeof(ALPHABET); j++) {
            if (data[i] == ALPHABET[j]) {
                translation.push_back(j);
                break;
            }
        }
    }

    return translation;
}

std::vector<uint8_t> Base62::decode(const std::vector<uint8_t> &data, size_t target_size) {
    std::vector<uint8_t> prepared = translate_decode(data);
    return convert(prepared, 62, 256, target_size);
}

void Base62::translate_encode(std::vector<uint8_t> &data, size_t data_size) {
    size_t i;

    for (i = 0; i < data_size; i++)
        data[i] = ALPHABET[data[i]];
}

std::vector<uint8_t> Base62::encode(std::vector<uint8_t> &data, size_t target_size) {
    std::vector<uint8_t> indices = convert(data, 256, 62, target_size);
    translate_encode(indices, target_size);
    return indices;
}
