#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "shared.h"
#include "base64.h"


Str *read_file(char *file_name)
{
    struct stat st;
    stat(file_name, &st);
    char *content = malloc(sizeof(char) * st.st_size);

    FILE *fp = fopen(file_name, "r");
    if (fp == NULL)
        return NULL;

    fread(content, st.st_size * sizeof(char), 1, fp);

    Str *s = malloc(sizeof(Str));
    s->str = content;
    s->size = st.st_size;
    return s;
}

/* c and strings is not comfy :( */
char *cstr_starts_with(const char *str, const char *substr)
{
    char *s1 = (char *)str;
    char *s2 = (char *)substr;
    char c1, c2;

    do {
        c1 = *s1++;
        c2 = *s2++;
        if (c2 == 0)
            return s1;
    } while (c1 == c2);

    return NULL;
}

void *ws_connect(void *p)
{
    WsConnectArgs *args = (WsConnectArgs *)p;
    int connfd = args->connfd;
    char *incoming_header = args->header;

    char request_key[WS_KEY_LEN + 1];
    /*
     * parse header
     * ....
     * or just grabbing the one field we need in the most conspicuous (and stupid) way :-)
     */
    char *a = strtok(incoming_header, "\n");
    do {
        char *res = cstr_starts_with(a, "Sec-WebSocket-Key:");
        if (res != NULL) {
            strncpy(request_key, res, WS_KEY_LEN);
            request_key[WS_KEY_LEN] = 0;
            break;
        }

    } while ((a = strtok(NULL, "\n")) != NULL);
    strcpy(request_key, "dGhlIHNhbXBsZSBub25jZQ==");
    LOG("found Sec-WebSocket-Key: %s", request_key);

    char key[WS_KEY_LEN + GUID_LEN + 1];
    // STOOPID!!!
    strcpy(key, request_key);
    strcpy(key + WS_KEY_LEN, GUID);
    LOG("compound key: %s", key);

    unsigned char digest[SHA1_DIGEST_LENGTH];
    SHA1((unsigned char *)key, 24 + GUID_LEN, digest);
    char *base64_digest = (char *)base64_encode(digest);
    LOG("computed Sec-Websocket-Accept: %s", base64_digest);

    int len = WS_HEADER_LEN + strlen(base64_digest);
    char outgoing_header[len];
    strcpy(outgoing_header, WS_HEADER);
    strcpy(outgoing_header + WS_HEADER_LEN, base64_digest);
    outgoing_header[len - 1] = '\n';
    LOG("outgoing header:\n{\n%s\n}\n", outgoing_header);
    int bytes_sent = send(connfd, outgoing_header, len, 0);
    if (bytes_sent == -1)
        LOG_ERR("failed to send packet :-(");
    else if (bytes_sent != len)
        LOG("packet only partially sent (%d of %d)", bytes_sent, len);
    else
        LOG("properly sent websocket upgrade to client");

    return NULL;
}


void *serve_file(void *arg)
{
    ServeFileArgs *args = (ServeFileArgs *)arg;
    int connfd = args->connfd;

    char out[4096];
    char header[] = "HTTP/1.0 200 OK\n"
        "Content-Type: text/html; charset=utf-8\n\n";

    char response[strlen(header) + args->file_content->size];
    strcpy(response, header);
    strcpy(response + strlen(header), args->file_content->str);
    //printf("%s\n", response);

    int n = strlen(response);
    int bytes_sent = send(connfd, response, n, 0);
    if (bytes_sent == -1)
        LOG_ERR("failed to send packet :-(");
    else if (bytes_sent != n)
        LOG("packet only partially sent (%d of %d)", bytes_sent, n);
    else
        LOG("properly served file");

    return NULL;
}

void *http_listen(void *arg)
{
    int connfd = *(int *)arg;
    char buf[1024];
    while (1) {
        int bytes_recv = recv(connfd, buf, 1024, 0);
        if (bytes_recv == 0) {
            LOG("remote closed connection: %d", connfd);
            return NULL;
        }

        printf("%s\n", buf);

        if (strstr(buf, "Sec-WebSocket-Key")) {
            LOG("WS UPGRADE START");
            WsConnectArgs args = { .header = buf, .connfd = connfd };
            ws_connect(&args);
            LOG("WS UPGRADE FINISHED");
        }

    }

    return NULL;
}

int main()
{
    /* create socket */
    int sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG_ERR("socket creation failed");
        exit(1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        LOG_ERR("socket SO_REUSEADDR option could not be set");

    LOG("socket successfully created");

    /*
     * has to be set to zero in order to properly pad the sin_zero[8] struct member
     */
    struct sockaddr_in servaddr = {0};

    /* assign IP and PORT */
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    /* binding newly created socket to given IP and verification */
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        LOG_ERR("socket bind failed");
        exit(1);
    }
    LOG("socket sucesfully binded");

    /* listen and verify */
    if ((listen(sockfd, 5)) != 0) {
        LOG_ERR("listen failed");
        exit(1);
    }
    LOG("server listening on port %d", PORT);

    Str *file_content = read_file("index.html");
    LOG("cached index.html");

    struct sockaddr_in client = {0};
    unsigned int len = sizeof(client);

    int connfd = accept(sockfd, (struct sockaddr *)&client, &len);
    if (connfd < 0) {
        LOG_ERR("server accept failed");
        exit(1);
    }
    LOG("server accepted the client: %d", connfd);
    ServeFileArgs args = { .file_content = file_content, .connfd = connfd };
    serve_file(&args);
    /* disable sending anymore packets to the client */
    shutdown(connfd, 1);

    /*
     * catch any other http requests
     */
    while (1) {
        struct sockaddr_in client = {0};
        unsigned int len = sizeof(client);

        int connfd = accept(sockfd, (struct sockaddr *)&client, &len);
        if (connfd < 0) {
            LOG_ERR("server accept failed");
            exit(1);
        }
        LOG("server accepted the client: %d", connfd);
        ServeFileArgs args = { .file_content = file_content, .connfd = connfd };
        pthread_t thread;
        pthread_create(&thread, NULL, http_listen, &connfd);
    }

    close(connfd);
    close(sockfd);
}
