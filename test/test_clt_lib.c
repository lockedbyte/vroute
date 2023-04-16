/*

Small utility to test VROUTE client shared libraries from command line

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef int (*vroute_clt_prototype)(char *host, int port, int proto, char *key, size_t key_sz);

void usage(void) {
    printf("==== { VROUTE CLIENT: USAGE } ===\n");
    printf("\n[0] => HTTPS protocol\n[1] => HTTP protocol\n[2] => Raw TCP protocol\n\n");
    printf("./test_clt_lib <lib path> <relay ip> <relay port> <protocol> <password>\n\n");
    printf("  Eg.: ./test_clt_lib ./libvroute_client.so 1.2.3.4 1337 0 p@ssw0rd1234#\n\n");
    return;
}

int main(int argc, char *argv[]) {
    char *relay_host = NULL;
    int relay_port = 0;
    int proto_n = 0;
    char *password = NULL;
    void *lib = NULL;
    vroute_clt_prototype func_p = NULL;
    char *lib_path = NULL;
    
    if(argc != 6) {
        usage();
        return 0;
    }
    
    lib_path = strdup(argv[1]);
    
    if(!lib_path)
        return 1;
    
    lib = dlopen(lib_path, RTLD_LAZY);
    if(!lib) {
        printf("Could NOT load library '%s' ('%s')...\n", lib_path, dlerror());
        return 1;
    }
    
    func_p = (vroute_clt_prototype)dlsym(lib, "start_relay_conn");
    if(!func_p)
        return 1;
    
    relay_host = strdup(argv[2]);
    relay_port = atoi(argv[3]);
    proto_n = atoi(argv[4]);
    
    password = strdup(argv[5]);
    

    
    if(!func_p(relay_host, relay_port, proto_n, password, strlen(password))) {
        puts("Unknown error occurred");
        
        if(relay_host) {
            free(relay_host);
            relay_host = NULL;
        }
        
        if(password) {
            free(password);
            password = NULL;
        }
        
        return 1;
    }
    
    if(relay_host) {
        free(relay_host);
        relay_host = NULL;
    }
        
    if(password) {
        free(password);
        password = NULL;
    }
    
    return 0;
}



