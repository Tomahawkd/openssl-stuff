//
// Created by Ghost on 2019-05-03.
//

#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST_NAME "127.0.0.1"
#define HOST_PORT "4433"

int verify(int t, X509_STORE_CTX *ctx) {
    return 1;
}

void handleFailure(int t) {
    long e = ERR_get_error();
    printf(ERR_error_string(e, NULL));
    exit(t);
}

int main() {

    long res = 1;

    SSL_CTX *ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLSv1_2_method();
    if (NULL == method) handleFailure(1);

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) handleFailure(2);

/* Cannot fail ??? */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify);

/* Cannot fail ??? */
    SSL_CTX_set_verify_depth(ctx, 4);

/* Cannot fail ??? */
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    web = BIO_new_ssl_connect(ctx);
    if (web == NULL) handleFailure(4);

    res = BIO_set_conn_hostname(web, HOST_NAME":"HOST_PORT);
    if (1 != res) handleFailure(5);
    
    BIO_get_ssl(web, &ssl);
    if (ssl == NULL) handleFailure(6);

    const char *const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    if (1 != res) handleFailure(7);

    res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
    if (1 != res) handleFailure(8);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (NULL == out) handleFailure(9);

    res = BIO_do_connect(web);
    if (1 != res) handleFailure(10);

    res = BIO_do_handshake(web);
    if (1 != res) handleFailure(11);

/* Step 1: verify a server certificate was presented during the negotiation */
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) { X509_free(cert); } /* Free immediately */
    if (NULL == cert) handleFailure(12);

/* Step 3: hostname verification */
/* An exercise left to the reader */

    BIO_puts(web, "GET / HTTP/1.1\r\n"
                  "Host: " HOST_NAME "\r\n"
                  "Connection: close\r\n\r\n");
    BIO_puts(out, "\n");

    int len = 0;
    do {
        char buff[1536] = {};
        len = BIO_read(web, buff, sizeof(buff));

        if (len > 0)
            BIO_write(out, buff, len);

    } while (len > 0 || BIO_should_retry(web));

    if (out)
        BIO_free(out);

    if (web != NULL)
        BIO_free_all(web);

    if (NULL != ctx)
        SSL_CTX_free(ctx);
}