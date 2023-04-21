CC=clang
#CC=gcc
CFLAGS=-Wno-deprecated-declarations -Wno-parentheses -Wno-unused-but-set-variable # -Wall -Werror

CLT_NAME=vrouteclt
SRV_NAME=vroutesrv
CLT_SL_NAME=libvroute_client.so
SRV_SL_NAME=libvroute_server.so

CLT_NAME_WIN=vrouteclt.exe
CLT_SL_NAME_WIN=libvroute_client.dll

WCC=x86_64-w64-mingw32-gcc

COMPILE_WIN_TARGET := vroute_win

ifeq ($(BUILD_DEBUG),1)
    CFLAGS+=-DDEBUG=1
else ifeq ($(BUILD_RELEASE),1)
    CFLAGS+=-O2 -DDEBUG=0
else ifeq ($(BUILD_DEV),1)
    CFLAGS+=-DDEBUG=1 -fsanitize=address -g
endif

WCFLAGS=$(CFLAGS) -DWINDOWS_OS=1 -I./ssl-include/ -L.

LIB_COMPILE_FLAGS=-fPIC -shared -DCOMPILE_AS_LIBRARY=1

all: vroute $(COMPILE_WIN_TARGET)

vroute:
	$(CC) $(CFLAGS) -fPIC -c tp/base64.c -o base64.o
	$(CC) $(CFLAGS) -fPIC -c util.c -o util.o
	$(CC) $(CFLAGS) -fPIC -lssl -lcrypto -c crypt.c -o crypt.o
	$(CC) $(CFLAGS) server.c -o $(SRV_NAME) -lssl -lcrypto -lpthread util.o crypt.o base64.o
	$(CC) $(CFLAGS) server.c $(LIB_COMPILE_FLAGS) -o $(SRV_SL_NAME) -lssl -lcrypto -lpthread util.o crypt.o base64.o

	$(CC) $(CFLAGS) client.c -o $(CLT_NAME) -lssl -lcrypto -lpthread util.o crypt.o base64.o
	$(CC) $(CFLAGS) client.c $(LIB_COMPILE_FLAGS) -o $(CLT_SL_NAME) -lssl -lcrypto -lpthread util.o crypt.o base64.o

	$(CC) $(CFLAGS) test/test_clt_lib.c -o test_clt_lib
	$(CC) $(CFLAGS) test/test_srv_lib.c -o test_srv_lib

vroute_win:
	$(WCC) $(WCFLAGS) -fPIC -c tp/base64.c -o w_base64.o
	$(WCC) $(WCFLAGS) -fPIC -c util.c -o w_util.o
	$(WCC) $(WCFLAGS) -fPIC -lssl -lcrypto -c crypt.c -o w_crypt.o
	$(WCC) $(WCFLAGS) wclient.c -o $(CLT_NAME_WIN) w_util.o w_crypt.o w_base64.o -lssl -lcrypto -lgdi32 -lmingw32 -lm -lws2_32 -lpthread -lcrypt32 -lwsock32 -static
	$(WCC) $(WCFLAGS) wclient.c $(LIB_COMPILE_FLAGS) -o $(CLT_SL_NAME_WIN) -shared w_util.o w_crypt.o w_base64.o -lssl -lcrypto -lgdi32 -lmingw32 -lm -lws2_32 -lpthread -lcrypt32 -lwsock32 -static

clean:
	rm -f vroutesrv vrouteclt libvroute_client.so libvroute_server.so
	rm -f *.o
	rm -f test_clt_lib
	rm -f test_srv_lib
	rm -f vrouteclt.exe libvroute_client.dll

