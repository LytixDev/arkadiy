#ifndef SHARED_H
#define SHARED_H

#include <stdlib.h>
#include <stdint.h>

#define MSG_LEN 1024
#define IP "127.0.0.1"
#ifndef WS_PORT
#  define WS_PORT 3001
#endif


#ifndef SHA1_DIGEST_LENGTH
#  define SHA1_DIGEST_LENGTH 20
#endif

#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define GUID_LEN strlen(GUID)
#define WS_KEY_LEN 24
#define WS_HEADER "HTTP/1.1 101 Switching Protocols\r\n"\
                "Upgrade: websocket\r\n"\
                "Connection: Upgrade\r\n"\
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


struct ws_frame_head_t {
    bool fin;
    int8_t opcode;
    size_t payload_len;
    uint8_t mask_key[4];
};

#endif /* SHARED_H */
