//
// Created by Ghost on 2018/11/13.
//

#ifndef CRYPTO_COMMON_ECB_H
#define CRYPTO_COMMON_ECB_H

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#ifdef DES_ECB
#include "des_ecb.h"
#endif

#ifdef AES_ECB
#include "aes_ecb.h"
#endif

#ifdef RC4_T
#include "rc4.h"
#endif

#define UEOF 255

void file_encrypt(crypto_data info, FILE *in_file, FILE *key_file, FILE *out_file) {
    unsigned char buffer[BUFFER_SIZE];
    unsigned char key[KEY_SIZE];

    // read key
    int c = 0;
    for (; (c < KEY_SIZE) && (feof(key_file) == 0); c++) {
        key[c] = (unsigned char) fgetc(key_file);
    }
    fclose(key_file);
    for (; c < KEY_SIZE; ++c) {
        key[c] = 0;
    }

    int count = 0;
    while (feof(in_file) == 0) {
        buffer[count] = (unsigned char) fgetc(in_file);
        if (buffer[count] == UEOF) {
            buffer[count] = 0;
            break;
        }

        count++;
        if (count == BUFFER_SIZE) {
            count = 0;

            unsigned char result[BUFFER_SIZE];
            encrypt(buffer, key, info.mode, result);

            // output
            for (int i = 0; i < BUFFER_SIZE; ++i) {
                if (result[i] == UEOF || result[i] == 0) break;
                fputc((int) result[i], out_file);
            }

            // clear buffer
            for (int j = 0; j < BUFFER_SIZE; ++j) {
                buffer[j] = 0;
            }
        }
    }

    fclose(in_file);

    if (count) {

        unsigned char result[BUFFER_SIZE];
        encrypt(buffer, key, info.mode, result);

        // output
        for (int i = 0; i < BUFFER_SIZE; ++i) {
            if (result[i] == UEOF || result[i] == 0) break;
            fputc((int) result[i], out_file);
        }
    }
    fclose(out_file);
}

#endif //CRYPTO_COMMON_ECB_H
