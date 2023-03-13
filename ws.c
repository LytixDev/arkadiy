#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <stdbool.h>

#include "shared.h"
#include "base64.h"
#define NICC_IMPLEMENTATION
#include "nicc/nicc.h"


struct darr_t *client_fds;


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

int ws_recv_frame_head(int fd, struct ws_frame_head_t *head)
{
    int8_t first_byte;

    if (recv(fd, &first_byte, 1, 0) < 1) {
        return -1;
    }

    head->fin = (first_byte & 0x80) == 0x80;
    head->opcode = first_byte & 0x0F;

    if (recv(fd, &first_byte, 1, 0) < 1) {
        return -1;
    }

    head->payload_len = first_byte & 0x7F;

    if (recv(fd, &head->mask_key, 4, 0) < 4) {
        return -1;
    }

    return 0;
}

int ws_send_frame_head(int fd, struct ws_frame_head_t *head)
{
    char response_head[2] = {0};
    int head_len = 0;
    if (head->payload_len <= 125) {
        *response_head = 0x81;
        *(response_head + 1) = head->payload_len;
        head_len = 2;
    } else {
        return -1;
    }

    if (send(fd, response_head, head_len, 0) < 0) {
        return -1;
    }

    return 0;
}

bool ws_handshake(int connfd, char *incoming_header)
{
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
    LOG("found Sec-WebSocket-Key: %s", request_key);

    // STOOPID!!!
    char key[WS_KEY_LEN + GUID_LEN + 1];
    strcpy(key, request_key);
    strcpy(key + WS_KEY_LEN, GUID);
    LOG("compound key: %s", key);

    unsigned char digest[SHA1_DIGEST_LENGTH];
    SHA1((unsigned char *)key, 24 + GUID_LEN, digest);
    char *base64_digest = (char *)base64_encode(digest);
    LOG("computed Sec-Websocket-Accept: %s", base64_digest);

    char outgoing_header[4096];
    sprintf(outgoing_header, "%s%s\r\n\r\n", WS_HEADER, base64_digest);
    int len = strlen(outgoing_header);

    LOG("outgoing header: {%s}", outgoing_header);
    if (send(connfd, outgoing_header, len, 0) <= 0)
        return false;

    return true;
}

void *ws_listen(void *arg)
{
    int connfd = *(int *)arg;
    char buf[MSG_LEN];

    /* perform handshake */
    LOG("handshake initiated");
    if (recv(connfd, buf, MSG_LEN, 0) <= 0) {
        LOG("remote closed connection: %d", connfd);
        goto close_sock;
    } else {
        if (ws_handshake(connfd, buf))
            LOG("handshake complete");
        else {
            LOG("handshake failed");
            goto close_sock;
        }
    }

    while (1) {
        struct ws_frame_head_t frame;
        if (ws_recv_frame_head(connfd, &frame) < 0) {
            LOG_ERR("Connection closed");
            goto close_sock;
        }
        
        if (ws_send_frame_head(connfd, &frame) < 0) {
            LOG_ERR("Failed to send head");
            continue;
        }

        int size = 0;
        do {
            int rec_len;
            if ((rec_len = recv(connfd, buf, MSG_LEN, 0)) < 0)
                break;
            
            size += rec_len;

            for (int i = 0; i < size; ++i)
                buf[i] ^= *(frame.mask_key + (i%4));

            buf[size] = 0;
            LOG("Received: %s", buf);

            if (send(connfd, buf, rec_len, 0) < 0)
                break;

            for (size_t i = 0; i < client_fds->size; i++) {
                int fd = *(int *)darr_get(client_fds, i);
                int rc;
                if (fd == connfd)
                    continue;
                if (ws_send_frame_head(fd, &frame) < 0) {
                    LOG_ERR("Failed to send head to %d", fd);
                    continue;
                }
                send(fd, buf, rec_len, 0);
                LOG("Sent %s to client %d that came from %d with rc %d", buf, fd, connfd, rc);
            }
            
        } while(size < frame.payload_len);
    }

close_sock:
    LOG("closing connection to %d", connfd);
    darr_rmv(client_fds, &connfd, sizeof(int));
    close(connfd);
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
    servaddr.sin_port = htons(WS_PORT);

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
    LOG("server listening on port %d", WS_PORT);
    client_fds = darr_malloc();

    while (1) {
        struct sockaddr_in client = {0};
        unsigned int len = sizeof(client);

        int connfd = accept(sockfd, (struct sockaddr *)&client, &len);
        if (connfd < 0) {
            LOG_ERR("server accept failed");
            exit(1);
        }
        LOG("server accepted the client: %d", connfd);

        int *fd = malloc(sizeof(int));
        *fd = connfd;
        darr_append(client_fds, fd);

        pthread_t thread;
        pthread_create(&thread, NULL, ws_listen, &connfd);
        //ws_listen(&connfd);
    }

    close(sockfd);
}
