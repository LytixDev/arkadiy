#include <string.h>
#include <stdlib.h>

#include "base64.h"


char base64_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};


unsigned char *base64_encode(unsigned char *str)
{
    char counts = 0;
    unsigned char buf[3];
    unsigned char *cipher = malloc(strlen((char *)str) * 4 / 3 + 4);
    int i = 0, c = 0;

    for (i = 0; str[i] != 0; i++) {
        buf[counts++] = str[i];
        if (counts == 3) {
            cipher[c++] = base64_map[buf[0] >> 2];
            cipher[c++] = base64_map[((buf[0] & 0x03) << 4) + (buf[1] >> 4)];
            cipher[c++] = base64_map[((buf[1] & 0x0f) << 2) + (buf[2] >> 6)];
            cipher[c++] = base64_map[buf[2] & 0x3f];
            counts = 0;
        }
    }

    if (counts > 0) {
        cipher[c++] = base64_map[buf[0] >> 2];
        if (counts == 1) {
            cipher[c++] = base64_map[(buf[0] & 0x03) << 4];
            cipher[c++] = '=';
        } else {
            cipher[c++] = base64_map[((buf[0] & 0x03) << 4) + (buf[1] >> 4)];
            cipher[c++] = base64_map[(buf[1] & 0x0f) << 2];
        }
        cipher[c++] = '=';
    }

    cipher[c] = 0;
    return cipher;
}
