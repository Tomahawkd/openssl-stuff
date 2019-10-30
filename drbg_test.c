//
// Created by Ghost on 2019/9/18.
//

#include <openssl/rand_drbg.h>
#include <stdio.h>

int main() {

    RAND_DRBG *drbg = RAND_DRBG_new(NID_aes_256_ctr, RAND_DRBG_FLAG_CTR_NO_DF, NULL);

    RAND_DRBG_instantiate(drbg, NULL, 0);

    uint8_t out[32];
    FILE *file = fopen("./random", "w");

    for (int i = 0; i < 32 * 1024 * 150; ++i) {
        RAND_DRBG_generate(drbg, out, 32, 0, NULL, 0);
        fwrite(out, 1, 32, file);
    }

    RAND_DRBG_uninstantiate(drbg);
    RAND_DRBG_free(drbg);
}