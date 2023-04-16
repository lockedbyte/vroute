/*

Small utility to test VROUTE server shared libraries from command line

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef int (*vroute_srv_prototype)(char *proxy_host, int proxy_port, char *relay_host, int relay_port, int proto, char *key, size_t key_sz, char *cert_file, int *err);

void usage(void) {
    printf("==== { VROUTE SERVER: USAGE } ===\n");
    printf("\n[0] => HTTPS protocol\n[1] => HTTP protocol\n[2] => Raw TCP protocol\n\n");
    printf("./test_srv_lib <lib path> <proxy ip> <proxy port> <relay ip> <relay port> <protocol> <password> <cert path (if https)>\n\n");
    printf("  Eg.: ./test_srv_lib ./libvroute_server.so 0.0.0.0 1080 0.0.0.0 1337 1 p@ssw0rd1234#\n\n");
    return;
}

int main(int argc, char *argv[]) {
    char *relay_host = NULL;
    char *proxy_host = NULL;
    int relay_port = 0;
    int proxy_port = 0;
    int proto_n = 0;
    char *password = NULL;
    char *cert_path = NULL;
    int err = 0;
    char *lib_path = NULL;
    void *lib = NULL;
    vroute_srv_prototype func_p = NULL;
    
    if(argc != 8) {
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
    
    func_p = (vroute_srv_prototype)dlsym(lib, "start_socks4_rev_proxy");
    if(!func_p)
        return 1;
    
    proxy_host = strdup(argv[2]);
    proxy_port = atoi(argv[3]);
    relay_host = strdup(argv[4]);
    relay_port = atoi(argv[5]);
    proto_n = atoi(argv[6]);
    
    if(proto_n == 0 && argc != 9) {
        usage();
        return 0;
    }

    password = strdup(argv[7]);
    
    if(proto_n == 0)
        cert_path = strdup(argv[8]);
        
    if(!password) {
        usage();
        return 0;
    }
    
    if(!func_p(proxy_host, proxy_port, relay_host, relay_port, proto_n, password, strlen(password), cert_path, &err)) {
        puts("Unknown error");
        
        if(relay_host) {
            free(relay_host);
            relay_host = NULL;
        }
        
        if(proxy_host) {
            free(proxy_host);
            proxy_host = NULL;
        }
        
        if(cert_path) {
            free(cert_path);
            cert_path = NULL;
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
    
    if(cert_path) {
        free(cert_path);
        cert_path = NULL;
    }
      
    if(proxy_host) {
        free(proxy_host);
        proxy_host = NULL;
    }
        
    if(password) {
        free(password);
        password = NULL;
    }
    
    return 0;
}
