#!/bin/bash

gcc -c tp/base64.c tp/base64.o
gcc -c util.c -o util.o
gcc -c crypt.c -o crypt.o

gcc client.c -o client -lssl -lcrypto -lpthread util.o crypt.o tp/base64.o

gcc server.c -o server -lssl -lcrypto -lpthread util.o crypt.o tp/base64.o
