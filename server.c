//
// Created by Ghost on 2019-05-03.
//

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int sock;
SSL_CTX *ctx;

int create_socket(int port) {
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *c;

    method = TLSv1_2_server_method();

    c = SSL_CTX_new(method);
    if (!c) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return c;
}

void configure_context(SSL_CTX *c) {
    SSL_CTX_set_ecdh_auto(c, 1);

    // Set the key and cert
    // Use openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
    if (SSL_CTX_use_certificate_file(c, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(c, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void cleanup() {
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int main(int argc, char **argv) {

    // sign ctrl-C for server shutting down
    signal(SIGINT, (void (*)(int)) cleanup);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_library_init();
    
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    // Handle connections
    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "HTTP/1.1 200 OK\r\nServer: Openssl\r\n\r\n";

        int client = accept(sock, (struct sockaddr *) &addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buf[2048];
            SSL_read(ssl, buf, sizeof(buf));
            printf("%s\n", buf);
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_free(ssl);
        close(client);
    }
}