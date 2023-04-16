/*

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
#include <ctype.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define MAX_CONCURRENT_PROXY_CLIENTS 1024
#define MAX_CONCURRENT_CLIENTS 1024
#define MAX_CONCURRENT_CHANNELS_PER_CLIENT 2048
#define MAX_CONCURRENT_QUEUED_BUFFERS MAX_CONCURRENT_CLIENTS * 256

typedef enum {
    HTTPS_COM_PROTO = 0,
    HTTP_COM_PROTO = 1,
    TCP_COM_PROTO = 2
} proto_t;

typedef enum {
    UNKNOWN_REQUEST_TYPE = 0,
    HANDSHAKE_SESSION_TYPE,
    DATA_REQUEST_TYPE,
    DATA_SENDING_TYPE,
} req_t;

typedef struct _channel_def {
    int channel_id;
    int client_id;
    int32_t dst_ip_addr;
    int16_t dst_port;
    int proxy_client_sock;
} channel_def;

typedef struct _conn_def {
    int client_id;
    int sock;
    proto_t proto;
    time_t last_conn_timestamp;
    int32_t client_ip_addr;
    int16_t orig_port;
    channel_def *c_channels;
} conn_def;

typedef struct buffer_queue buffer_queue;

struct buffer_queue {
    int queue_id;
    int client_id;
    size_t size;
    time_t queue_time;
    buffer_queue *next;
    char data[0];
};

typedef struct _proxy_client_def {
    int proxy_client_id;
    int sock;
    int channel_id;
    int32_t client_ip_addr;
    int16_t orig_port;
} proxy_client_def;

typedef struct _http_handshake_def {
    int h_id;
    char *challenge;
    char *solution;
    int is_solved;
    int fail;
    size_t sol_size;
} http_handshake_def;

typedef struct __attribute__((packed)) _socks_hdr {
    uint8_t vn;
    uint8_t cd;
    uint16_t dstport;
    uint32_t dstip;
    uint8_t null_c;
} socks_hdr;

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
    FORWARD_CONNECTION_FAILURE,
    CMD_DATA_LAST_NULL_ENTRY
} scmd_t;

typedef enum {
    SERVER_UNKNOWN_ERR = 1,
    INVALID_PARAMETER = 2,
    OUT_OF_MEMORY_ERROR = 3,
    // ...
} srv_error_t;

typedef struct _arg_pass {
    char *host;
    int port;
    proto_t proto;
} arg_pass;

typedef struct _rl_arg_pass {
    int sock;
    SSL *c_ssl;
    int is_https;
} rl_arg_pass;

typedef struct _cmd_def {
    int cmd;
    unsigned char value;
    char *name;
} cmd_def;

typedef struct _conn_open_req {
    int is_routed;
    int channel_id;
    int client_id;
    uint32_t ip;
    uint16_t port;
    int client_id_arr[MAX_CONCURRENT_CLIENTS];
} conn_open_req;

typedef enum {
    UNKNOWN_LOG_LEVEL = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_ERROR,
} log_level_t;

void collect_dead_clients_worker(void);
void ping_worker(void);
void __ping_worker(void);
void shutdown_srv(void);
uint64_t generate_client_id(void);
uint64_t generate_proxy_client_id(void);
uint64_t generate_queue_id(void);
uint64_t generate_channel_id(void);
int handshake_sess_exists(int h_id);
void generate_random_challenge(char *chall, size_t chall_sz);
int is_challenge_solved(int h_id);
int is_challenge_failure(int h_id);
int mark_challenge_solved(int h_id);
int mark_challenge_failure(int h_id);
int create_handshake(int h_id);
int delete_handshake(int h_id);
char *get_challenge(int h_id);
char *get_h_challenge_solution(int h_id, size_t *out_size);
int channel_exists(int channel_id);
int create_channel(int client_id, int proxy_sock, char *host, int port);
int create_channel_custom(int channel_id, int client_id, int proxy_sock, char *host, int port);
int send_remote_cmd(scmd_t cmd, int channel_id);
int close_channel(int channel_id, int is_client_req);
int get_client_by_channel_id(int channel_id);
int get_proxy_sock_by_channel_id(int channel_id);
int is_channel_by_client(int client_id, int channel_id);
int client_exists(int client_id);
int create_client(int sock, char *client_ip, int client_port, proto_t proto);
int close_client(int client_id);
int update_last_conn_time(int client_id);
void close_all_clients(void);
void close_all_proxy_clients(void);
int proxy_client_exists(int proxy_client_id);
int create_proxy_client(int sock, char *client_ip, int client_port, int channel_id);
int close_proxy_client(int proxy_client_id);
int get_channel_by_proxy_client_id(int proxy_client_id);
int get_sock_by_proxy_client_id(int proxy_client_id);
int get_relay_sock_by_client_id(int client_id);
int queue_exists(int queue_id);
int queue_data(int client_id, char *data, size_t data_sz, time_t timestamp);
int remove_queued_data(int queue_id);
char *get_queued_data(int queue_id, size_t *out_size);
char *get_next_queued_data(int client_id, size_t *out_size);
int parse_socks_hdr(char *data, size_t data_sz, char **host, int *port);
int __interpret_remote_packet(int client_id, char *data, size_t data_sz);
size_t get_real_size_pad(size_t size, int bs);
int interpret_remote_packet(int client_id, char *data, size_t data_sz);
char *pack_proxy_data(int channel_id, char *data, size_t size, size_t *out_size);
char *get_challenge_solution(char *challenge, size_t size, size_t *out_size, char *key, size_t key_sz);
int handshake(int sock);
int relay_tcp_srv_poll(int sock);
ssize_t http_write_all(int sock, SSL *c_ssl, char **data, size_t *data_sz, int is_https);
ssize_t http_read_all(int sock, SSL *c_ssl, char **data, size_t *data_sz, int is_https);
int get_get_param(char *data, size_t data_sz, int is_handshake);
char *get_data_from_http(char *data, size_t data_sz, size_t *out_size);
char *get_http_data_response(char *data, size_t data_sz, size_t *out_size);
int is_client_in_checked_list(int client_id);
int mark_route_found(int client_id, int channel_id, int found);
int is_route_discovery_in_process(void);
char *get_route_req_open_cmd(int client_id, size_t *out_size);
int issue_connection_open(int proxy_sock, uint32_t ip_addr, uint16_t port);
char *interpret_http_req(char *data, size_t data_sz, size_t *out_size);
int relay_http_srv_handle_req(rl_arg_pass *arg);
void proxy_srv_poll(int sock);
void start_proxy_srv(arg_pass *arg);
void ssl_initialization(void);
void ssl_cleanup(void);
int do_http_relay_srv(char *host, int port);
int do_tcp_relay_srv(char *host, int port);
void start_relay_srv(arg_pass *arg);
int is_valid_host_or_ip_addr(char *str);
int is_valid_proxy_or_relay_port(int port);
int start_socks4_rev_proxy(char *proxy_host, int proxy_port, char *relay_host, int relay_port, proto_t proto, char *key, size_t key_sz, char *cert_file, int *err);







