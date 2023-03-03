#ifndef SHARED_H
#define SHARED_H

#include <stdlib.h>

#define MSG_LEN 1024
#define IP "127.0.0.1"
#ifndef WS_PORT
#  define WS_PORT 8080
#endif
#ifndef PORT
#  define PORT 8080
#endif


#ifndef SHA1_DIGEST_LENGTH
#  define SHA1_DIGEST_LENGTH 20
#endif

#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define GUID_LEN strlen(GUID)
#define WS_KEY_LEN 24
#define WS_HEADER "HTTP/1.1 101 Switching Protocols\n"\
                "Upgrade: websocket\n"\
                "Connection: Upgrade\n"\
                "Sec-WebSocket-Protocol: chat\n"\
                "Sec-WebSocket-Accept: "

#define WS_HEADER_LEN strlen(WS_HEADER)



#define LOG(...) \
    do { \
        printf("\033[0;33m[LOG]: "); \
        printf(__VA_ARGS__); \
        printf("\033[0m\n"); \
    } while (0) \

#define LOG_ERR(...) \
    do { \
        fprintf(stderr, "\033[0;31m[LOG]: "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\033[0m\n"); \
    } while (0) \


/* Pascal string */
typedef struct {
    char *str;
    size_t size;
} Str;

typedef struct {
    Str *file_content;
    int connfd;
} ServeFileArgs;

typedef struct {
    char *header;
    int connfd;
} WsConnectArgs;

#endif /* SHARED_H */
