/*

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#ifndef WINDOWS_OS
#include <sys/ioctl.h>
#else
#include <windows.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#endif

#include "util.h"

#define PREFIX_HEXDUMP_OUTPUT "[VROUTE] [DEBUG]"

#define CONN_TIMEOUT 4

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

void __hexdump(const char *func_name, char *tag, void *mem, size_t len) {
    unsigned int i = 0, j = 0;
    
    if(!func_name || !tag || !mem || len == 0)
        return;
        
    printf("\n%s %s: %s:\n\n", PREFIX_HEXDUMP_OUTPUT, func_name, tag);
        
    for(i = 0 ; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0) ; i++) {
            if(i % HEXDUMP_COLS == 0)
                printf("\t0x%06x: ", i);

            if(i < len)
                printf("%02x ", 0xFF & ((char*)mem)[i]);
            else
                printf("   ");

            if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
                for(j = i - (HEXDUMP_COLS - 1) ; j <= i ; j++) {
                    if(j >= len)
                        putchar(' ');
                    else if(isprint(((char*)mem)[j]))
                        putchar(0xFF & ((char*)mem)[j]);
                    else
                        putchar('.');
                }
                putchar('\n');
            }
    }
    putchar('\n');
    return;
}

void *memdup(const void *mem, size_t size) {
    void *out = calloc(size + 1, sizeof(char));
    if(out != NULL)
        memcpy(out, mem, size);
    return out;
}

ssize_t write_all(int sock, char **data, size_t *data_sz) {
    int r = 0;
    size_t sent = 0;
    char *ptr = NULL;
    size_t sz = 0;
    time_t start = time(NULL);
    time_t curr = 0;

    if(sock < 0 || !data || !data_sz)
        return -1;

    if(data && data_sz) {
        ptr = *data;
        sz = *data_sz;
    }

    while(sent < sz) {
        curr = time(NULL);
        if((curr - start) >= CONN_TIMEOUT)
            return -1;
        r = send(sock, ptr, sz - sent, 0);
        if(r < 0)
           return -1;
        sent += r;
    }

    return sent;
}

ssize_t read_all(int sock, char **data, size_t *data_sz) {
    #if WINDOWS_OS
    long bytes_available = 0;
    #else
    int bytes_available = 0;
    #endif
    size_t sent = 0;
    int r = 0;
    char *ptr = NULL;
    time_t start = time(NULL);
    time_t curr = 0;

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
        curr = time(NULL);
        if((curr - start) >= CONN_TIMEOUT)
            return -1;
        r = recv(sock, ptr, bytes_available - sent, 0);
        if(r < 0)
            return -1;
        sent += r;
    }

    *data = ptr;
    *data_sz = bytes_available;

    return sent;
}


