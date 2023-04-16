CC=clang
#CC=gcc
CFLAGS=-Wno-deprecated-declarations -Wno-parentheses -Wno-unused-but-set-variable # -Wall -Werror

ifeq ($(BUILD_DEBUG),1)
    CFLAGS+=-DDEBUG=1
else ifeq ($(BUILD_RELEASE),1)
    CFLAGS+=-O2 -DDEBUG=0
else ifeq ($(BUILD_DEV),1)
    CFLAGS+=-DDEBUG=1 -fsanitize=address -g
endif

LIB_COMPILE_FLAGS=-fPIC -shared -DCOMPILE_AS_LIBRARY=1

all: vroute

vroute:
	$(CC) $(CFLAGS) -fPIC -c tp/base64.c -o base64.o
	$(CC) $(CFLAGS) -fPIC -c util.c -o util.o
	$(CC) $(CFLAGS) -fPIC -c crypt.c -o crypt.o
	$(CC) $(CFLAGS) server.c -o vroutesrv -lssl -lcrypto -lpthread util.o crypt.o base64.o
	$(CC) $(CFLAGS) server.c $(LIB_COMPILE_FLAGS) -o libvroute_server.so -lssl -lcrypto -lpthread util.o crypt.o base64.o
	
	$(CC) $(CFLAGS) client.c -o vrouteclt -lssl -lcrypto -lpthread util.o crypt.o base64.o
	$(CC) $(CFLAGS) client.c $(LIB_COMPILE_FLAGS) -o libvroute_client.so -lssl -lcrypto -lpthread util.o crypt.o base64.o
	
	$(CC) $(CFLAGS) test/test_clt_lib.c -o test_clt_lib
	$(CC) $(CFLAGS) test/test_srv_lib.c -o test_srv_lib

clean:
	rm -f vroutesrv vrouteclt libvroute_client.so libvroute_server.so
	rm -f *.o
	rm -f test_clt_lib
	rm -f test_srv_lib
