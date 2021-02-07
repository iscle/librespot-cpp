//
// Created by Iscle on 07/02/2021.
//

#include "aes_audio_decrypt.h"

static uint8_t AUDIO_AES_IV[] = {
        0x72, 0xe0, 0x67, 0xfb, 0xdd, 0xcb, 0xcf, 0x77, 0xeb, 0xe8, 0xbc, 0x64, 0x3f, 0x63, 0x0d, 0x93
};

AesAudioDecrypt::AesAudioDecrypt(std::vector<uint8_t> key) :
        key(std::move(key)), cipher(AES(AES::AES_128_CTR)) {
}

void AesAudioDecrypt::decrypt_chunk(int chunk_index, std::vector<uint8_t> buffer) {

}