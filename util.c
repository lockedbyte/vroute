/*

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "util.h"

int file_exists(const char *path) {
    FILE *file = NULL;

    if(!path)
        return 0;

    if((file = fopen(path, "r")) != NULL) {
        if(file) {
            fclose(file);
            file = NULL;
        }
        return 1;
    }

    return 0;
}

void *memdup(const void *mem, size_t size) {
    void *out = calloc(size, sizeof(char));
    if(out != NULL)
        memcpy(out, mem, size);
    return out;
}

ssize_t write_all(int sock, char **data, size_t *data_sz) {
    int r = 0;
    size_t sent = 0;
    char *ptr = NULL;
    size_t sz = 0;

    if(sock < 0 || !data || !data_sz)
        return -1;

    if(data && data_sz) {
        ptr = *data;
        sz = *data_sz;
    }

    while(sent < sz) {
        r = write(sock, ptr, sz - sent);
        if(r < 0)
           return -1;
        sent += r;
    }

    return sent;
}

ssize_t read_all(int sock, char **data, size_t *data_sz) {
    int bytes_available = 0;
    size_t sent = 0;
    int r = 0;
    char *ptr = NULL;

    if(sock < 0 || !data || !data_sz)
        return -1;

    *data = NULL;
    *data_sz = 0;

    #if WINDOWS_OS
    r = ioctlsocket(sock, FIONREAD, &bytes_available);
    #else
    r = ioctl(sock, FIONREAD, &bytes_available);
    #endif
    if(r < 0)
        return -1;

    if(bytes_available < 0) {
        *data = NULL;
        *data_sz = 0;
        return 0;
    }

    ptr = calloc(bytes_available + 1, sizeof(char));
    if(!ptr)
        return -1;

    while(sent < bytes_available) {
        r = read(sock, ptr, bytes_available - sent);
        if(r < 0)
            return -1;
        sent += r;
    }

    *data = ptr;
    *data_sz = bytes_available;

    return sent;
}


