//
// Created by Iscle on 07/02/2021.
//

#ifndef LIBRESPOT_CPP_AES_AUDIO_DECRYPT_H
#define LIBRESPOT_CPP_AES_AUDIO_DECRYPT_H


#include <cstdint>
#include <vector>
#include "../../crypto/aes.h"

class AesAudioDecrypt {
public:
    AesAudioDecrypt(std::vector<uint8_t> key);

private:
    std::vector<uint8_t> key;
    AES cipher;

    int decrypt_count;
    int decrypt_total_time;

    void decrypt_chunk(int chunk_index, std::vector<uint8_t> buffer);
};


#endif //LIBRESPOT_CPP_AES_AUDIO_DECRYPT_H
