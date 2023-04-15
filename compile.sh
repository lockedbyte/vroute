#!/bin/bash

clang -g -c tp/base64.c tp/base64.o
clang -g -c util.c -o util.o
clang -g -c crypt.c -o crypt.o

clang -fsanitize=address -DCLIENT_COMPILE=1 -g client.c -o client -lssl -lcrypto -lpthread util.o crypt.o tp/base64.o

clang -fsanitize=address -DSERVER_COMPILE=1 -g server.c -o server -lssl -lcrypto -lpthread util.o crypt.o tp/base64.o
