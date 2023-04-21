/*

Repository: https://github.com/lockedbyte/vroute

-------------------------------- [ User notes ] --------------------------------

A brief message
===================

It is advised, if you are using proxychains as your SOCKS proxy client, to change
in /etc/proxychains.conf these values to the following:

tcp_read_time_out 150000
tcp_connect_time_out 80000

Also, no need to mention you need to point the SOCKS proxy address and port to the
one set up with this project.


Future additions
==================

- change encryption to the new OpenSSL encryption escheme using EVP
- allow second-order connections for nodes to increase remote accessibility within the network map


Compilation
===================

Simply:

$ make


Usage and environment setup
===============================

Server:

- Use libvroute_server.so on your C2 server
- Use vroutesrv command line tool

Client:

- Use libvroute_client.so from your implant
- Use vrouteclt command line tool (not recommended)


About HTTPS
===============

You will need a certificate for setting up the HTTPS version.

If you just want to test, you can simply:

$ openssl req -newkey rsa:2048 -nodes -keyout cert.pem -x509 -days 365 -out cert.pem

And then pass the path to cert.pem to the server initialization entrypoing

------------------------------- [ End User notes ] -------------------------------

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

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "util.h"
#include "crypt.h"
#include "tp/base64.h"

#include "server.h"

#define VROUTE_VERSION "1.0.0"

#define CHALLENGE_DEFAULT_SIZE 64

#define COMMAND_CHANNEL 0

#define POLL_TIMEOUT 2000

#define IN_ANY_ADDR "0.0.0.0"

#define MAX_HOSTNAME_SIZE 255

#define ROUTE_REQUEST_PROCESS_TIMEOUT 20 /* 10 seconds */

#define MAX_KEY_SIZE 64

#define PNG_FAKE_HDR "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"
#define PNG_FAKE_HDR_SIZE 8

#define DATA_PREFIX "<img src='data:image/jpeg;base64,"
#define DATA_SUFFIX "' />"

#define DATA_INPUT_PREFIX "token="
#define DATA_INPUT_SUFFIX "; expire=0;"

#define MIN_CLIENT_ID 11111
#define MAX_CLIENT_ID 60000

#define MIN_CHANNEL_ID 11111
#define MAX_CHANNEL_ID 60000

#define VR_LOG(...) vr_log(__func__, __VA_ARGS__)

#if DEBUG
#define hexdump(tag, mem, size) __hexdump(__func__, tag, mem, size)
#else
#define hexdump(tag, mem, size) ((void)0)
#endif

#define MAX_LOG_MESSAGE_SIZE 4096
#define LOG_PREFIX_STR "[VROUTE]"

#define UNLIMITED_OPPORTUNITIES 1

/*

Source: https://www.openssh.com/txt/socks4.protocol

1) CONNECT

The client connects to the SOCKS server and sends a CONNECT request when
it wants to establish a connection to an application server. The client
includes in the request packet the IP address and the port number of the
destination host, and userid, in the following format.

		+----+----+----+----+----+----+----+----+----+----+....+----+
		| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
		+----+----+----+----+----+----+----+----+----+----+....+----+
 # of bytes:	   1    1      2              4           variable       1

VN is the SOCKS protocol version number and should be 4. CD is the
SOCKS command code and should be 1 for CONNECT request. NULL is a byte
of all zero bits.

The SOCKS server checks to see whether such a request should be granted
based on any combination of source IP address, destination IP address,
destination port number, the userid, and information it may obtain by
consulting IDENT, cf. RFC 1413.  If the request is granted, the SOCKS
server makes a connection to the specified port of the destination host.
A reply packet is sent to the client when this connection is established,
or when the request is rejected or the operation fails. 

		+----+----+----+----+----+----+----+----+
		| VN | CD | DSTPORT |      DSTIP        |
		+----+----+----+----+----+----+----+----+
 # of bytes:	   1    1      2              4

VN is the version of the reply code and should be 0. CD is the result
code with one of the following values:

	90: request granted
	91: request rejected or failed
	92: request rejected becasue SOCKS server cannot connect to
	    identd on the client
	93: request rejected because the client program and identd
	    report different user-ids

The remaining fields are ignored.

The SOCKS server closes its connection immediately after notifying
the client of a failed or rejected request. For a successful request,
the SOCKS server gets ready to relay traffic on both directions. This
enables the client to do I/O on its connection as if it were directly
connected to the application server.

*/

/* VN=0, CD=0x5a (success), dstport, dstip (ignored) */
#define SOCKS_REPLY_SUCCESS "\x00\x5a\xff\xff\xff\xff\xff\xff"

/* VN=0, CD=0x5b (failure / rejected), dstport, dstip (ignored) */
#define SOCKS_REPLY_FAILURE "\x00\x5b\xff\xff\xff\xff\xff\xff"

#define AES_IV_SIZE 16

//#define MIN_IV_CHAR_RANGE 0x1
//#define MAX_IV_CHAR_RANGE 0xff

#define MIN_CHALL_CHR_VAL 0x01
#define MAX_CHALL_CHR_VAL 0xff

#define MAX_KEY_SIZE 64

#define LAST_CONN_GAP_THRESHOLD 60 * 5 // 5 minutes

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
    },
    [CMD_DATA_LAST_NULL_ENTRY] = {
        .cmd = 0,
        .value = 0,
        .name = ""
    }
};

int close_srv = 0;
conn_def *client_conns = NULL;
proxy_client_def *proxy_client_conns = NULL;

buffer_queue *queue_head = NULL;

http_handshake_def *handshake_defs = NULL;

conn_open_req *conn_req_glb = NULL;

pthread_mutex_t glb_structure_lock;

pthread_mutex_t proxy_glb_conn_lock;
pthread_mutex_t client_glb_conn_lock;
pthread_mutex_t handshake_glb_conn_lock;
pthread_mutex_t queue_glb_buf_lock;
pthread_mutex_t dead_client_worker;
pthread_mutex_t conn_req_lock;

pthread_mutex_t iopen_lock;
pthread_mutex_t route_open_lock;

char *_key = NULL;
size_t _key_sz = 0;
proto_t _proto = 0;
char *_cert_file = NULL;

SSL_CTX *_ctx = NULL;

void collect_dead_clients_worker(void) {
    time_t last;
    time_t curr = time(NULL);
    long gap = 0;
    
    // XXX: disable dead client collector
    //   to fix bug in which alive connections
    //   are being collected
    while(1) {}
    
    pthread_mutex_lock(&dead_client_worker);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id != 0 && (client_conns[i].proto == HTTP_COM_PROTO ||
                                    client_conns[i].proto == HTTPS_COM_PROTO)) {
            last = client_conns[i].last_conn_timestamp;

            gap = curr - last;

            if(gap > LAST_CONN_GAP_THRESHOLD) {
                close_client(client_conns[i].client_id);
            }
        }
    }
    
    pthread_mutex_unlock(&dead_client_worker);
   
    return;
}

void ping_worker(void) {
    while(1) {
        sleep(10);

        if(close_srv) {
            pthread_exit(NULL);
            return;
        }

        collect_dead_clients_worker();
    }
    pthread_exit(NULL);
    return;
}

void __ping_worker(void) {
    pthread_t th;
    pthread_create(&th, NULL, (void *)ping_worker, NULL);
    return;
}

void shutdown_srv(void) {
    close_srv = 1;
    return;
}

void vr_log(const char *func_name, log_level_t log_level, const char *format_str, ...) {
    char message[MAX_LOG_MESSAGE_SIZE + 1] = { 0 };
    char *log_level_prefix = NULL;
    
    if(!func_name || !format_str)
        return;
    
    if(log_level == UNKNOWN_LOG_LEVEL)
        return;
        
    #if !DEBUG
    if(log_level == LOG_DEBUG)
        return;
    #endif
        
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

uint64_t generate_client_id(void) {
    uint64_t client_id = (rand() % (MAX_CLIENT_ID - MIN_CLIENT_ID + 1)) + MIN_CLIENT_ID;
    return client_id;
}

uint64_t generate_proxy_client_id(void) {
    return generate_client_id();
}

uint64_t generate_queue_id(void) {
    return generate_client_id();
}

uint64_t generate_channel_id(void) {
    uint64_t channel_id = (rand() % (MAX_CHANNEL_ID - MIN_CHANNEL_ID + 1)) + MIN_CHANNEL_ID;
    return channel_id;
}

int handshake_sess_exists(int h_id) {
    int idx = -1;
   
    if(h_id <= 0)
        return 0;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return 1;
}

void generate_random_challenge(char *chall, size_t chall_sz) {
    if(!chall || chall_sz == 0)
        return;
   
    for(int i = 0 ; i < chall_sz ; i++)
        chall[i] = (rand() % (MAX_CHALL_CHR_VAL - MIN_CHALL_CHR_VAL + 1)) + MIN_CHALL_CHR_VAL;
   
    return;
}

int is_challenge_solved(int h_id) {
    int idx = -1;
    int r = 0;
   
    if(h_id <= 0)
        return 0;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find handshake definition with handshake sess ID: %d", h_id);
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }
   
    r = handshake_defs[idx].is_solved;
    if(r == 0) {
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return 1;
}

int is_challenge_failure(int h_id) {
    int idx = -1;
    int r = 0;
   
    if(h_id <= 0)
        return 0;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find handshake definition with handshake sess ID: %d", h_id);
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }

    r = handshake_defs[idx].fail;
    if(r == 0) {
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return 1;
}

int mark_challenge_solved(int h_id) {
    int idx = -1;
   
    if(h_id <= 0)
        return 0;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find handshake definition with handshake sess ID: %d", h_id);
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }

    handshake_defs[idx].is_solved = 1;

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return 1;
}

int mark_challenge_failure(int h_id) {
    int idx = -1;
   
    if(h_id <= 0)
        return 0;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find handshake definition with handshake sess ID: %d", h_id);
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }

    handshake_defs[idx].fail = 1;

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return 1;
}

int create_handshake(int h_id) {
    int idx = -1;
    char chall[CHALLENGE_DEFAULT_SIZE + 1] = { 0 };
    char *sol_a = NULL;
    char *sol = NULL;
    size_t sol_size_a = 0;
    size_t sol_size = 0;

    if(h_id <= 0)
        return 0;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == 0) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find free slot for handshake definition");
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }
   
    generate_random_challenge(chall, CHALLENGE_DEFAULT_SIZE);
   
    sol_a = encrypt_challenge((char *)chall, CHALLENGE_DEFAULT_SIZE, _key, _key_sz, &sol_size_a);
    if(!sol_a) {
        VR_LOG(LOG_ERROR, "Error trying to encrypt generated challenge");
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }
   
    sol = sha256_hash(sol_a, sol_size_a, &sol_size);
    if(!sol) {
        if(sol_a) {
            free(sol_a);
            sol_a = NULL;
        }
        VR_LOG(LOG_ERROR, "Error hashing solution in SHA-256");
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }

    if(sol_a) {
        free(sol_a);
        sol_a = NULL;
    }
   
    handshake_defs[idx].h_id = h_id;
    handshake_defs[idx].challenge = memdup(chall, CHALLENGE_DEFAULT_SIZE);
    handshake_defs[idx].solution = sol;
    handshake_defs[idx].sol_size = sol_size;
    handshake_defs[idx].is_solved = 0;
    handshake_defs[idx].fail = 0;

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return 1;
}

int delete_handshake(int h_id) {
    int idx = -1;
   
    if(h_id <= 0)
        return 0;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
   
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find handshake definition with handshake sess ID: %d", h_id);
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return 0;
    }
   
    handshake_defs[idx].h_id = 0;
    handshake_defs[idx].is_solved = 0;
    handshake_defs[idx].fail = 0;

    if(handshake_defs[idx].challenge) {
        free(handshake_defs[idx].challenge);
        handshake_defs[idx].challenge = NULL;
    }

    if(handshake_defs[idx].solution) {
        free(handshake_defs[idx].solution);
        handshake_defs[idx].solution = NULL;
    }

    handshake_defs[idx].sol_size = 0;

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return 1;
}

char *get_challenge(int h_id) {
    int idx = -1;
    char *chall = NULL;
   
    if(h_id <= 0)
        return NULL;
        
    pthread_mutex_lock(&handshake_glb_conn_lock);
   
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find handshake definition with handshake sess ID: %d", h_id);
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return NULL;
    }

    chall = handshake_defs[idx].challenge;

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    return chall;
}

char *get_h_challenge_solution(int h_id, size_t *out_size) {
    int idx = -1;
    char *sol = NULL;
    size_t sol_size = 0;
   
    if(h_id <= 0 || !out_size)
        return NULL;

    *out_size = 0;
    
    pthread_mutex_lock(&handshake_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(handshake_defs[i].h_id == h_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find handshake definition with handshake sess ID: %d", h_id);
        pthread_mutex_unlock(&handshake_glb_conn_lock);
        return NULL;
    }

    sol = handshake_defs[idx].solution;
    sol_size = handshake_defs[idx].sol_size;

    pthread_mutex_unlock(&handshake_glb_conn_lock);
    
    *out_size = sol_size;
    return sol;
}

/* XXX: locking relies on caller */
int channel_exists(int channel_id) {
    int idx = -1;
    int c_idx = -1;
   
    if(channel_id <= 0)
        return 0;

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; x++) {
            if(client_conns[i].c_channels && client_conns[i].c_channels[x].channel_id == channel_id) {
                c_idx = i;
                idx = x;
                break;
            }
        }
    }
   
    if(idx == -1 || c_idx == -1) {
        return 0;
    }
   
    return 1;
}


int create_channel(int client_id, int proxy_sock, char *host, int port) {
    int c_idx = -1;
    int idx = -1;
    int channel_id = 0;
    int32_t dst_ip_addr = 0;
   
    if(client_id <= 0 || proxy_sock < 0 || !host || port <= 0)
        return 0;
        
    pthread_mutex_lock(&client_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id == client_id) {
            c_idx = i;
            break;
        }
    }
   
    if(c_idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find client connection with client ID: %d", client_id);
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; i++) {
        if(client_conns[c_idx].c_channels && client_conns[c_idx].c_channels[i].channel_id == 0) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find free slot for channel definition");
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }

    dst_ip_addr = inet_addr(host);
  
    while(channel_id = generate_channel_id()) {
        if(!channel_exists(channel_id))
            break;
    }

    client_conns[c_idx].c_channels[idx].channel_id = channel_id;
    client_conns[c_idx].c_channels[idx].client_id = client_id;
    client_conns[c_idx].c_channels[idx].dst_ip_addr = dst_ip_addr;
    client_conns[c_idx].c_channels[idx].dst_port = (int16_t)port;
    client_conns[c_idx].c_channels[idx].proxy_client_sock = proxy_sock;

    pthread_mutex_unlock(&client_glb_conn_lock);
    return channel_id;
}

int create_channel_custom(int channel_id, int client_id, int proxy_sock, char *host, int port) {
    int c_idx = -1;
    int idx = -1;
    int32_t dst_ip_addr = 0;
   
    if(client_id <= 0 || proxy_sock < 0 || !host || port <= 0)
        return 0;
        
    //pthread_mutex_lock(&client_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id == client_id) {
            c_idx = i;
            break;
        }
    }
   
    if(c_idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find client connection with client ID: %d", client_id);
       // pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; i++) {
        if(client_conns[c_idx].c_channels && client_conns[c_idx].c_channels[i].channel_id == 0) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find free slot for channel definition");
      // pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }

    dst_ip_addr = inet_addr(host);

    client_conns[c_idx].c_channels[idx].channel_id = channel_id;
    client_conns[c_idx].c_channels[idx].client_id = client_id;
    client_conns[c_idx].c_channels[idx].dst_ip_addr = dst_ip_addr;
    client_conns[c_idx].c_channels[idx].dst_port = (int16_t)port;
    client_conns[c_idx].c_channels[idx].proxy_client_sock = proxy_sock;

   // pthread_mutex_unlock(&client_glb_conn_lock);
    return channel_id;
}

int send_remote_cmd(scmd_t cmd, int channel_id) {
    char *p = NULL;
    size_t p_sz = 0;
    tlv_header *tlv = NULL;
    s_cmd *cmd_p = NULL;
    int client_id = 0;
    int rsock = 0;
    ssize_t rx = 0;
    char *enc = NULL;
    size_t enc_sz = 0;
  
    if(channel_id <= 0)
        return 0;
    
    switch(cmd) {
        case CHANNEL_CLOSE_CMD:
        case RELAY_CLOSE_CMD:
        case PING_CMD:
            break;
        case CHANNEL_OPEN_CMD:			/* issued independently */
        case FORWARD_CONNECTION_SUCCESS:	/* server-only command */
        case FORWARD_CONNECTION_FAILURE:	/* server-only command */
        case UNKNOWN_CMD:			/* unknown command */
        default:
            return 0;
    }
  
    p_sz = sizeof(tlv_header) + sizeof(s_cmd);
    p = calloc(p_sz, sizeof(char));
    if(!p)
        return 0;
    tlv = (tlv_header *)p;
    cmd_p = ((s_cmd *)(p + sizeof(tlv_header)));

    client_id = get_client_by_channel_id(channel_id);
    if(client_id <= 0) {
        VR_LOG(LOG_ERROR, "Error getting client ID by channel ID: %d", channel_id);
        return 0;
    }
  
    tlv->client_id = client_id;
    tlv->channel_id = COMMAND_CHANNEL;
    tlv->tlv_data_len = sizeof(s_cmd);
  
    cmd_p->cmd = cmd_def_data[cmd].value;
    cmd_p->channel_id = channel_id;
    
    VR_LOG(LOG_INFO, "Sending command '%s'", cmd_def_data[cmd].name);
  
    if(_proto == TCP_COM_PROTO) {
        rsock = get_relay_sock_by_client_id(client_id);
        if(rsock < 0) {
            VR_LOG(LOG_ERROR, "Error getting relay sock by client ID: %d", client_id);
            return 0;
        }
        
        enc = encrypt_data(p, p_sz, _key, _key_sz, &enc_sz);
        if(!enc) {
            VR_LOG(LOG_ERROR, "Error trying to encrypt data");
            return 0;
        }

        rx = write_all(rsock, &enc, &enc_sz);
        if(rx < 0) {
            VR_LOG(LOG_ERROR, "Error writing to TCP relay clients");
            return 0;
        }
        
        if(enc) {
            free(enc);
            enc = NULL;
        }
    } else if(_proto == HTTP_COM_PROTO || 
                _proto == HTTPS_COM_PROTO) {
        if(!queue_data(client_id, p, p_sz, time(NULL))) {
            VR_LOG(LOG_ERROR, "Error trying to queue data");
            return 0;
        }
    }
    
    // XXX: fix p memory leaks on this function
    
    if(p) {
        free(p);
        p = NULL;  
    }

    return 1;
}

int close_channel(int channel_id, int is_client_req) {
    int idx = -1;
    int c_idx = -1;
   
    if(channel_id <= 0)
        return 0;
        
   // pthread_mutex_lock(&client_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; x++) {
            if(client_conns[i].c_channels && client_conns[i].c_channels[x].channel_id == channel_id) {
                c_idx = i;
                idx = x;
                break;
            }
        }
    }
   
    if(idx == -1 || c_idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find channel definition with channel ID: %d", channel_id);
      //  pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    client_conns[c_idx].c_channels[idx].channel_id = 0;
    client_conns[c_idx].c_channels[idx].client_id = 0;
    client_conns[c_idx].c_channels[idx].dst_ip_addr = 0;
    client_conns[c_idx].c_channels[idx].dst_port = 0;
   
    if(client_conns[c_idx].c_channels[idx].proxy_client_sock != -1) {
        close(client_conns[c_idx].c_channels[idx].proxy_client_sock);
        client_conns[c_idx].c_channels[idx].proxy_client_sock = -1;
    }
   
    if(!is_client_req) {
        if(!send_remote_cmd(CHANNEL_CLOSE_CMD, channel_id)) {
            VR_LOG(LOG_ERROR, "Error sending remote cmd 'CHANNEL_CLOSE_CMD' to channel ID: %d", channel_id);
     //       pthread_mutex_unlock(&client_glb_conn_lock);
            return 0;
        }
    }
  
 //   pthread_mutex_unlock(&client_glb_conn_lock);
    return 1;
}

int get_client_by_channel_id(int channel_id) {
    int idx = -1;
    int c_idx = -1;
    int client_id = 0;
   
    if(channel_id <= 0)
        return 0;
        
    pthread_mutex_lock(&client_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; x++) {
            if(client_conns[i].c_channels && client_conns[i].c_channels[x].channel_id == channel_id) {
                c_idx = i;
                idx = x;
                break;
            }
        }
    }
   
    if(idx == -1 || c_idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find channel definition with channel ID: %d", channel_id);
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    client_id = client_conns[c_idx].c_channels[idx].client_id;
   
    pthread_mutex_unlock(&client_glb_conn_lock);
    return client_id;
}

int get_proxy_sock_by_channel_id(int channel_id) {
    int idx = -1;
    int c_idx = -1;
    int proxy_client_sock = 0;
   
    if(channel_id <= 0)
        return 0;
        
    pthread_mutex_lock(&client_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; x++) {
            if(client_conns[i].c_channels && client_conns[i].c_channels[x].channel_id == channel_id) {
                c_idx = i;
                idx = x;
                break;
            }
        }
    }
   
    if(idx == -1 || c_idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find channel definition with channel ID: %d", channel_id);
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    proxy_client_sock = client_conns[c_idx].c_channels[idx].proxy_client_sock;
    
    pthread_mutex_unlock(&client_glb_conn_lock);
    return proxy_client_sock;
}

int is_channel_by_client(int client_id, int channel_id) {
    int idx = -1;
    int c_idx = -1;
    int cid = 0;
   
    if(client_id <= 0 || channel_id <= 0)
        return 0;
        
    pthread_mutex_lock(&client_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; x++) {
            if(client_conns[i].c_channels && client_conns[i].c_channels[x].channel_id == channel_id) {
                c_idx = i;
                idx = x;
                break;
            }
        }
    }
   
    if(idx == -1 || c_idx == -1) {
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    cid = client_conns[c_idx].c_channels[idx].client_id;
   
    if(cid != client_id) {
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    pthread_mutex_unlock(&client_glb_conn_lock);
    return 1;
}

/* XXX: locking relies on caller! */
int client_exists(int client_id) {
    int idx = -1;
   
    if(client_id <= 0)
        return 0;

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id == client_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1)
        return 0;
      
    return 1;
}

/* XXX: sock == -1 if HTTP(S) */
int create_client(int sock, char *client_ip, int client_port, proto_t proto) {
    int idx = -1;
    int client_id = 0;
    int32_t client_ip_addr = 0;
    channel_def *c_channels = NULL;
   
    pthread_mutex_lock(&client_glb_conn_lock);
   
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id == 0) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find client connection with client ID: %d", client_id);
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
  
    if(client_ip)
        client_ip_addr = inet_addr(client_ip);
  
    while(client_id = generate_client_id()) {
        if(!client_exists(client_id))
            break;
    }
  
    c_channels = (channel_def *)calloc(MAX_CONCURRENT_CHANNELS_PER_CLIENT, sizeof(channel_def));
    if(!c_channels) {
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
  
    client_conns[idx].client_id = client_id;
    client_conns[idx].sock = sock;
    client_conns[idx].proto = proto;
    client_conns[idx].last_conn_timestamp = time(NULL);
    client_conns[idx].client_ip_addr = client_ip_addr;
    client_conns[idx].orig_port = (int16_t)client_port;
    client_conns[idx].c_channels = c_channels;

    pthread_mutex_unlock(&client_glb_conn_lock);
    return client_id;
}

/* XXX: locking relies on caller */
int close_client(int client_id) {
    int idx = -1;
  
    if(client_id <= 0)
        return 0;
        
  //  pthread_mutex_lock(&client_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id == client_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find client connection with client ID: %d", client_id);
   //     pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    client_conns[idx].client_id = 0;
    client_conns[idx].proto = 0;
    client_conns[idx].last_conn_timestamp = 0;
    client_conns[idx].client_ip_addr = 0;
    client_conns[idx].orig_port = 0;
   
    for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; x++) {
        if(client_conns[idx].c_channels && client_conns[idx].c_channels[x].channel_id != 0) {
            client_conns[idx].c_channels[x].channel_id = 0;
            client_conns[idx].c_channels[x].client_id = 0;
            client_conns[idx].c_channels[x].dst_ip_addr = 0;
            client_conns[idx].c_channels[x].dst_port = 0;
	   
            if(client_conns[idx].c_channels[x].proxy_client_sock != -1) {
                close(client_conns[idx].c_channels[x].proxy_client_sock);
                client_conns[idx].c_channels[x].proxy_client_sock = -1;
            }
        }
    }
   
    if(client_conns[idx].c_channels) {
        free(client_conns[idx].c_channels);
        client_conns[idx].c_channels = NULL;
    }
   
    if(client_conns[idx].sock != -1) {
        close(client_conns[idx].sock);
        client_conns[idx].sock = -1;
    }
  
 //   pthread_mutex_unlock(&client_glb_conn_lock);
    return 1;
}

int update_last_conn_time(int client_id) {
    int idx = -1;
  
    if(client_id <= 0)
        return 0;
        
    pthread_mutex_lock(&client_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id == client_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find client connection with client ID: %d", client_id);
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }
   
    client_conns[idx].last_conn_timestamp = time(NULL);
  
    pthread_mutex_unlock(&client_glb_conn_lock);
    return 1;
}

void close_all_clients(void) {
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id != 0) {
            close_client(client_conns[i].client_id);
        }
    }
    return;
}

void close_all_proxy_clients(void) {
    for(int i = 0 ; i < MAX_CONCURRENT_PROXY_CLIENTS ; i++) {
        if(proxy_client_conns[i].proxy_client_id != 0) {
            close_proxy_client(proxy_client_conns[i].proxy_client_id);
        }
    }
    return;
}

/* XXX: locking relies on caller */
int proxy_client_exists(int proxy_client_id) {
    int idx = -1;
   
    if(proxy_client_id <= 0)
        return 0;

    for(int i = 0 ; i < MAX_CONCURRENT_PROXY_CLIENTS ; i++) {
        if(proxy_client_conns[i].proxy_client_id == proxy_client_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        return 0;
    }
    
    return 1;
}

int create_proxy_client(int sock, char *client_ip, int client_port, int channel_id) {
    int idx = -1;
    int proxy_client_id = 0;
    int32_t client_ip_addr = 0;

    if(sock < 0 || channel_id <= 0)
        return 0;
        
    pthread_mutex_lock(&proxy_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_PROXY_CLIENTS ; i++) {
        if(proxy_client_conns[i].proxy_client_id == 0) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find free slot for proxy client connection");
        pthread_mutex_unlock(&proxy_glb_conn_lock);
        return 0;
    }

    while(proxy_client_id = generate_proxy_client_id()) {
        if(!proxy_client_exists(proxy_client_id))
            break;
    }
  
    if(client_ip)
        client_ip_addr = inet_addr(client_ip);
   
    proxy_client_conns[idx].proxy_client_id = proxy_client_id;
    proxy_client_conns[idx].sock = sock;
    proxy_client_conns[idx].client_ip_addr = client_ip_addr;
    proxy_client_conns[idx].orig_port = (int16_t)client_port;
    proxy_client_conns[idx].channel_id = channel_id;

    pthread_mutex_unlock(&proxy_glb_conn_lock);
    return proxy_client_id;
}

int close_proxy_client(int proxy_client_id) {
    int idx = -1;
  
    if(proxy_client_id <= 0)
        return 0;
        
    pthread_mutex_lock(&proxy_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_PROXY_CLIENTS ; i++) {
        if(proxy_client_conns[i].proxy_client_id == proxy_client_id) {
            idx = i;
            break;
        }
    }
   
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find proxy client connection with proxy client ID: %d", proxy_client_id);
        pthread_mutex_unlock(&proxy_glb_conn_lock);
        return 0;
    }

    proxy_client_conns[idx].proxy_client_id = 0;
    proxy_client_conns[idx].client_ip_addr = 0;
    proxy_client_conns[idx].orig_port = 0;
    proxy_client_conns[idx].channel_id = 0;
   
    if(proxy_client_conns[idx].sock != -1) {
        close(proxy_client_conns[idx].sock);
        proxy_client_conns[idx].sock = -1;
    }
  
    pthread_mutex_unlock(&proxy_glb_conn_lock);
    return 1;
}

int get_channel_by_proxy_client_id(int proxy_client_id) {
    int idx = -1;
    int channel_id = 0;
  
    if(proxy_client_id <= 0)
        return 0;
        
    pthread_mutex_lock(&proxy_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_PROXY_CLIENTS ; i++) {
        if(proxy_client_conns[i].proxy_client_id == proxy_client_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find proxy client connection with proxy client ID: %d", proxy_client_id);
        pthread_mutex_unlock(&proxy_glb_conn_lock);
        return 0;
    }
   
    channel_id = proxy_client_conns[idx].channel_id;
    
    pthread_mutex_unlock(&proxy_glb_conn_lock);
    return channel_id;
}

int get_sock_by_proxy_client_id(int proxy_client_id) {
    int idx = -1;
    int sock = 0;

    if(proxy_client_id <= 0)
        return 0;
        
    pthread_mutex_lock(&proxy_glb_conn_lock);
     
    for(int i = 0 ; i < MAX_CONCURRENT_PROXY_CLIENTS ; i++) {
        if(proxy_client_conns[i].proxy_client_id == proxy_client_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find proxy client connection with proxy client ID: %d", proxy_client_id);
        pthread_mutex_unlock(&proxy_glb_conn_lock);
        return 0;
    }
   
    sock = proxy_client_conns[idx].sock;
   
    pthread_mutex_unlock(&proxy_glb_conn_lock);
    return sock;
}

int get_relay_sock_by_client_id(int client_id) {
    int idx = -1;
    int sock = 0;
  
    if(client_id <= 0)
        return 0;
        
    pthread_mutex_lock(&client_glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(client_conns[i].client_id == client_id) {
            idx = i;
            break;
        }
    }

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Could not find client connection with client ID: %d", client_id);
        pthread_mutex_unlock(&client_glb_conn_lock);
        return 0;
    }

    sock = client_conns[idx].sock;

    pthread_mutex_unlock(&client_glb_conn_lock);
    return sock;
}

/* XXX: locking relies on caller */
int queue_exists(int queue_id) {
    buffer_queue *p = NULL;
    int found = 0;

    if(queue_id <= 0)
        return 0;

    p = queue_head;
    while(p) {
        if(p->queue_id == queue_id) {
            found = 1;
            break;
        }
        p = p->next;
    }

    if(!found) {
        return 0;
    }

    return 1;
}

int queue_data(int client_id, char *data, size_t data_sz, time_t timestamp) {
    int queue_id = 0;
    buffer_queue *qbuf = NULL;
    buffer_queue *p = NULL;
    char *qbuf_data = NULL;
   
    if(client_id <= 0 || !data || data_sz == 0)
        return 0;
        
    pthread_mutex_lock(&queue_glb_buf_lock);
      
    while(queue_id = generate_queue_id()) {
        if(!queue_exists(queue_id))
            break;
    }
      
    qbuf = (buffer_queue *)calloc(sizeof(buffer_queue) + data_sz, sizeof(char));
    if(!qbuf) {
        pthread_mutex_unlock(&queue_glb_buf_lock);
        return 0;
    }
    qbuf_data = &qbuf->data[0];

    qbuf->queue_id = queue_id;
    qbuf->client_id = client_id;
    qbuf->size = data_sz;
    qbuf->queue_time = timestamp;
    qbuf->next = NULL;
  
    memcpy(qbuf_data, data, data_sz);
  
    p = queue_head;
  
    if(!p) {
        queue_head = qbuf;
    } else {
        while(p->next != NULL) {
            p = p->next;
        }

        if(p->next != NULL) {
            VR_LOG(LOG_ERROR, "Rare behaviour: p->next != NULL");
            pthread_mutex_unlock(&queue_glb_buf_lock);
            return 0;
        }

        p->next = qbuf;
    }

    pthread_mutex_unlock(&queue_glb_buf_lock);
    return queue_id;
}

int remove_queued_data(int queue_id) {
    buffer_queue *qbuf = NULL;
    char *qbuf_data = NULL;
    buffer_queue *p = NULL;
    buffer_queue *prev = NULL;
    int found = 0;
   
    if(queue_id <= 0)
        return 0;
        
    pthread_mutex_lock(&queue_glb_buf_lock);
   
    prev = NULL;
    p = queue_head;
    while(p) {
        if(p->queue_id == queue_id) {
            found = 1;
            break;
        }
        prev = p;
        p = p->next;
    }

    if(!found) {
        VR_LOG(LOG_ERROR, "Could not find queued data with queue_id: %d", queue_id);
        pthread_mutex_unlock(&queue_glb_buf_lock);
        return 0;
    }

    qbuf = p;

    qbuf_data = &qbuf->data[0];

    if(prev) {
        prev->next = p->next;
    } else {
        queue_head = p->next;
    }

    memset(qbuf_data, 0, qbuf->size);
  
    qbuf->queue_id = 0;
    qbuf->client_id = 0;
    qbuf->size = 0;
    qbuf->queue_time = 0;
    qbuf->next = NULL;
  
    if(qbuf) {
        free(qbuf);
        qbuf = NULL;
    }
    
    pthread_mutex_unlock(&queue_glb_buf_lock);
    return 1;
}

char *get_queued_data(int queue_id, size_t *out_size) {
    char *out = NULL;
    buffer_queue *qbuf = NULL;
    char *qbuf_data = NULL;
    size_t data_size = 0;
    buffer_queue *p = NULL;
    buffer_queue *prev = NULL;
    int found = 0;
   
    if(queue_id <= 0 || !out_size)
        return NULL;
     
    *out_size = 0;
    
    pthread_mutex_lock(&queue_glb_buf_lock);
   
    prev = NULL;
    p = queue_head;
    while(p) {
        if(p->queue_id == queue_id) {
            found = 1;
            break;
        }
        prev = p;
        p = p->next;
    }
   
    if(!found) {
        VR_LOG(LOG_INFO, "No queue_id (%d) found with data in queue", queue_id);
        pthread_mutex_unlock(&queue_glb_buf_lock);
        return 0;
    }
      
    qbuf = p;
   
    qbuf_data = &qbuf->data[0];
   
    if(prev) {
        prev->next = p->next;
    } else {
        queue_head = p->next;
    }
   
    out = memdup(qbuf_data, qbuf->size);
    if(!out) {
        pthread_mutex_unlock(&queue_glb_buf_lock);
        return NULL;
    }
    data_size = qbuf->size;
   
    memset(qbuf_data, 0, qbuf->size);
  
    qbuf->queue_id = 0;
    qbuf->client_id = 0;
    qbuf->size = 0;
    qbuf->queue_time = 0;
    qbuf->next = NULL;
  
    if(qbuf) {
        free(qbuf);
        qbuf = NULL;
    }
    
    pthread_mutex_unlock(&queue_glb_buf_lock);
  
    *out_size = data_size;
     
    return out;
}

char *get_next_queued_data(int client_id, size_t *out_size) {
    char *out = NULL;
    buffer_queue *qbuf = NULL;
    char *qbuf_data = NULL;
    size_t data_size = 0;
    buffer_queue *p = NULL;
    buffer_queue *prev = NULL;
    int found = 0;
   
    if(client_id <= 0 || !out_size)
        return NULL;
     
    *out_size = 0;
    
    pthread_mutex_lock(&queue_glb_buf_lock);
   
    prev = NULL;
    p = queue_head;
    while(p) {
        if(p->client_id == client_id) {
            found = 1;
            break;
        }
        prev = p;
        p = p->next;
    }

    if(!found) {
        VR_LOG(LOG_INFO, "No data for client ID (%d) in data queue", client_id);
        pthread_mutex_unlock(&queue_glb_buf_lock);
        return NULL;
    }
      
    qbuf = p;

    qbuf_data = &qbuf->data[0];

    if(prev) {
        prev->next = p->next;
    } else {
        queue_head = p->next;
    }

    out = memdup(qbuf_data, qbuf->size);
    if(!out) {
        pthread_mutex_unlock(&queue_glb_buf_lock);
        return NULL;
    }
    data_size = qbuf->size;

    memset(qbuf_data, 0, qbuf->size);
  
    qbuf->queue_id = 0;
    qbuf->client_id = 0;
    qbuf->size = 0;
    qbuf->queue_time = 0;
    qbuf->next = NULL;
  
    if(qbuf) {
        free(qbuf);
        qbuf = NULL;
    }
    
    pthread_mutex_unlock(&queue_glb_buf_lock);
  
    *out_size = data_size;
     
    return out;
}

int parse_socks_hdr(char *data, size_t data_sz, char **host, int *port) {
    socks_hdr *s_hdr = NULL;
    char *host_string = NULL;
    struct in_addr ip_struct;
  
    if(!data || data_sz == 0 || !host || !port)
        return 0;
    
    *host = NULL;
    *port = 0;

    if(data_sz < sizeof(socks_hdr))
        return 0;
     
    s_hdr = (socks_hdr *)data;
  
    host_string = calloc(INET_ADDRSTRLEN + 1, sizeof(char));
    if(!host_string)
        return 0;
        
    ip_struct.s_addr = s_hdr->dstip;

    if(inet_ntop(AF_INET, &ip_struct, host_string, INET_ADDRSTRLEN) == NULL) {
        VR_LOG(LOG_ERROR, "Error in inet_ntop()");
        return 0;
    }
  
    *host = host_string;
    *port = ntohs(s_hdr->dstport);

    return 1;
}

int __interpret_remote_packet(int client_id, char *data, size_t data_sz) {
    int channel_id = 0;
    int cid = 0;
    size_t tlv_sz = 0;
    tlv_header *tlv = NULL;
    ssize_t rx = 0;
    int proxy_sock = 0;
    char *data_x = NULL;
    size_t data_sz_x = 0;
    s_cmd *cmd_p = NULL;
    uint8_t cmd = 0;
    int found = 0;
    int cmd_c = 0;
  
    if(client_id <= 0 || !data || data_sz == 0)
        return 0;
  
    if(data_sz < sizeof(tlv_header))
        return 0;
  
    tlv = (tlv_header *)data;
  
    cid = tlv->client_id;
    channel_id = tlv->channel_id;
    tlv_sz = tlv->tlv_data_len;
  
    if(cid < 0 || channel_id < 0 || tlv_sz == 0)
        return 0;
      
    if(tlv_sz >= data_sz)
        return 0;
      
    if(tlv_sz > (data_sz - sizeof(tlv_header)))
        return 0;
  
    data_x = (data + sizeof(tlv_header));
    data_sz_x = tlv_sz;
  
    if(channel_id == COMMAND_CHANNEL) {
        if(data_sz_x < sizeof(s_cmd))
            return 0;
            
        VR_LOG(LOG_INFO, "Received packet is a command");
  
        cmd_p = (s_cmd *)data_x;    
        cmd = cmd_p->cmd;
        
        for(int i = 0 ; i < CMD_DATA_LAST_NULL_ENTRY ; i++) {
            if(cmd_def_data[i].value == cmd) {
                found = 1;
                cmd_c = i;
                break;
            }
        }
        
        if(!found) {
            VR_LOG(LOG_ERROR, "Unknown command received");
            return 0;
        }
        
        found = 0;
      
      /*
        if(channel_id != cmd_p->channel_id) {
            VR_LOG(LOG_ERROR, "channel ID (%d) and channel ID in message (%d) do not coincide", channel_id, cmd_p->channel_id);
            return 0;
        }
      */
        switch(cmd_c) {
            case CHANNEL_CLOSE_CMD: {
                VR_LOG(LOG_INFO, "Received a CHANNEL_CLOSE_CMD command");
                
                if(!close_channel(cmd_p->channel_id, 1)) {
                    VR_LOG(LOG_ERROR, "Error trying to close channel ID: %ld", cmd_p->channel_id);
                    return 0;
                }
                return 1;
            }
            case PING_CMD: {
                VR_LOG(LOG_INFO, "Received a PING_CMD command");
                
                if(!update_last_conn_time(client_id)) {
                    VR_LOG(LOG_ERROR, "Error updating last connetion time for client ID: %ld", client_id);
                    return 0;
                }
                return 1;
            }
            case FORWARD_CONNECTION_SUCCESS:
                VR_LOG(LOG_INFO, "Received a FORWARD_CONNECTION_SUCCESS command");
                found = 1;
            case FORWARD_CONNECTION_FAILURE:
                if(!found)
                    VR_LOG(LOG_INFO, "Received a FORWARD_CONNECTION_FAILURE command");
                    
                if(found) {
                    VR_LOG(LOG_DEBUG, "Received FORWARD_CONNECTION_SUCCESS for channel_id: %d", cmd_p->channel_id);
                } else {
                    VR_LOG(LOG_DEBUG, "Received FORWARD_CONNECTION_FAILURE for channel_id: %d", cmd_p->channel_id);
                }
                
                if(channel_exists(cmd_p->channel_id)) {
                    VR_LOG(LOG_WARN, "Channel ID %d already exists", cmd_p->channel_id);
                    if(!found) {
                        if(!close_channel(cmd_p->channel_id, 1)) {
                            VR_LOG(LOG_ERROR, "Error trying to close channel ID: %d", cmd_p->channel_id);
                            return 0;
                        }
                        return 1;
                    }
                    VR_LOG(LOG_ERROR, "Channel already opened, we are not supposed to receive FORWARD_CONNECTION_SUCCESS messages");
                    return 0;
                }
                
                if(is_route_solved(cmd_p->channel_id)) {
                    VR_LOG(LOG_DEBUG, "Route already solved by some other client, skipping...");
                    return 1;
                } 
                
                /*
                if(is_client_in_checked_list(cmd_p->channel_id)) {
                    VR_LOG(LOG_INFO, "This client has already been checked: No access to requested destination");
                    return 1;
                }
                */
                
                if(!mark_route_found(client_id, cmd_p->channel_id, found)) {
                    VR_LOG(LOG_ERROR, "Could not mark route as found");
                    return 0;
                }
                    
                return 1;
            case UNKNOWN_CMD:      /* unknown command */
            case CHANNEL_OPEN_CMD: /* client-only command */
            case RELAY_CLOSE_CMD:  /* client-only command */
            default:
                VR_LOG(LOG_ERROR, "Invalid command received");
                return 0;
        }
    } else {
        VR_LOG(LOG_INFO, "Received packet is data to relay to SOCKS proxy client");
        
        proxy_sock = get_proxy_sock_by_channel_id(channel_id);
        if(proxy_sock < 0) {
            VR_LOG(LOG_ERROR, "Error trying to get proxy client sock by channel ID: %d", channel_id);
            return 0;
        }
      
        rx = write_all(proxy_sock, &data_x, &data_sz_x);
        if(rx < 0) {
            VR_LOG(LOG_ERROR, "Error writing data to corresponding proxy client");
            return 0;
        }
    }
  
    return 1;
}

size_t get_real_size_pad(size_t size, int bs) {
    if((size % bs) == 0)
        return size + bs;
    return size + (bs - (size % bs));
}

int interpret_remote_packet(int client_id, char *data, size_t data_sz) {
    tlv_header *tlv = NULL;
    size_t rmndr_sz = 0;
    size_t curr_pkt_sz = 0;
    char *p = NULL;
    int success = 0;
    size_t real_size = 0;
    char *unpadded = NULL;
    size_t unpadded_sz = 0;
    int i = 0;
    
    if(client_id <= 0 || !data || data_sz == 0)
        return 0;
        
    if(data_sz < sizeof(tlv_header))
        return 0;
        
    VR_LOG(LOG_DEBUG, "Starting unpacking of received data packets...");
    
    p = data;
    rmndr_sz = data_sz;
    while(rmndr_sz > 0) {
        i++;
        
        if(rmndr_sz < sizeof(tlv_header)) {
            VR_LOG(LOG_ERROR, "Remaining size less than tlv header size...");
            break;
        }

        tlv = (tlv_header *)p;
        
        curr_pkt_sz = tlv->tlv_data_len;
        if(curr_pkt_sz > (rmndr_sz - sizeof(tlv_header))) {
            VR_LOG(LOG_ERROR, "Packet size exceeds bounds (pkt size: %ld, rmndr_sz: %ld)...", curr_pkt_sz, rmndr_sz);
            break;
        }
            
        VR_LOG(LOG_DEBUG, "Packet #%d with data length: %d", i, curr_pkt_sz);
        
        if(rmndr_sz > sizeof(tlv_header) + curr_pkt_sz) {
            real_size = get_real_size_pad(sizeof(tlv_header) + curr_pkt_sz, 16);
            
            VR_LOG(LOG_DEBUG, "Package is likely to be padded: real size: %d", real_size);
            
            unpadded = PKCS7_unpad(p, real_size, 16, &unpadded_sz);
            if(unpadded) {
                hexdump("packet", unpadded, unpadded_sz);
                
                VR_LOG(LOG_DEBUG, "PKCS7 unpadding worked, interpreting packet...");
                if(__interpret_remote_packet(client_id, unpadded, unpadded_sz))
                    success = 1;
                
                // XXX: make sure about the assumption
                p += (real_size + AES_BLOCK_SIZE);
                rmndr_sz -= (real_size + AES_BLOCK_SIZE);
                continue;
            }
            
            VR_LOG(LOG_DEBUG, "Unpadding did NOT work, fallbacking to normal interpreting...");
        }
        
        hexdump("packet", p, sizeof(tlv_header) + curr_pkt_sz);
        
        VR_LOG(LOG_DEBUG, "Interpreting packet...");
        
        if(__interpret_remote_packet(client_id, p, sizeof(tlv_header) + curr_pkt_sz))
            success = 1;
            
        p += (sizeof(tlv_header) + curr_pkt_sz);
        rmndr_sz -= (sizeof(tlv_header) + curr_pkt_sz);
    }
    
    if(rmndr_sz > 0) {
        VR_LOG(LOG_WARN, "There are %d bytes of remainder in the received data...", rmndr_sz);
    }
    
    if(!success) {
        VR_LOG(LOG_ERROR, "None of the interpreted packets succeed...");
        return 0;
    }
        
    return 1;
}

char *pack_proxy_data(int channel_id, char *data, size_t size, size_t *out_size) {
    int client_id = 0;
    tlv_header *tlv = NULL;
    char *p = NULL;
   
    if(channel_id <= 0 || !data || size == 0 || !out_size)
        return NULL;
      
    *out_size = 0;
   
    p = calloc(sizeof(tlv_header) + size, sizeof(char));
    if(!p)
        return NULL;
    tlv = (tlv_header *)p;
   
    client_id = get_client_by_channel_id(channel_id);
    if(client_id <= 0) {
        VR_LOG(LOG_ERROR, "Error trying to get client ID by channel ID: %d", channel_id);
        return NULL;
    }
   
    tlv->client_id = client_id;
    tlv->channel_id = channel_id;
    tlv->tlv_data_len = size;
   
    memcpy(p + sizeof(tlv_header), data, size);
   
    *out_size = (sizeof(tlv_header) + size);
    return p;
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
    
    if(out_size_x == 0) {
        VR_LOG(LOG_ERROR, "Error: Encrypted challenge size is 0");
        return NULL;
    }
        
    sol = sha256_hash(ptr, out_size_x, &s_out_size);
    if(!sol) {
        if(ptr) {
            free(ptr);
            ptr = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to hash encrypted challenge with SHA-256");
        return NULL;
    }
        
    if(ptr) {
        free(ptr);
        ptr = NULL;
    }
    
    *out_size = s_out_size;
    return sol;
}

int handshake(int sock) {
    int r = 0;
    char chall[CHALLENGE_DEFAULT_SIZE + 1] = { 0 };
    size_t out_size = 0;
    char *p = NULL;
    uint32_t cid = 0;
    char *p_clt = NULL;
    int err = 0;

    if(sock < 0)
       return 0;

    generate_random_challenge(chall, CHALLENGE_DEFAULT_SIZE);
    
    hexdump("challenge", chall, CHALLENGE_DEFAULT_SIZE);

    p = get_challenge_solution(chall, CHALLENGE_DEFAULT_SIZE, &out_size, _key, _key_sz);
    if(!p || out_size == 0) {
        VR_LOG(LOG_ERROR, "Error when getting challenge solution");
        err = 1;
        goto end;
    }
    
    hexdump("challenge solution", p, out_size);

    p_clt = calloc(out_size, sizeof(char));
    if(!p_clt) {
        err = 1;
        goto end;
    }

    r = write(sock, chall, CHALLENGE_DEFAULT_SIZE);
    if(r <= 0) {
        VR_LOG(LOG_ERROR, "Error trying to send challenge to client");
        err = 1;
        goto end;
    }

    r = read(sock, p_clt, out_size);
    if(r <= 0) {
        VR_LOG(LOG_ERROR, "Error trying to receive solution from client");
        err = 1;
        goto end;
    }
    
    hexdump("client-provided solution", p_clt, out_size);

    if(r != out_size) {
        VR_LOG(LOG_ERROR, "Provided input size is not the same size as the solution");
        err = 1;
        goto end;
    }

    if(memcmp(p_clt, p, out_size) != 0) {
        VR_LOG(LOG_INFO, "Client failed authentication with a wrong challenge solution");
        cid = 0;
    } else {
        VR_LOG(LOG_INFO, "Client succeed providing right solution for challenge");
        cid = create_client(sock, NULL, 0, TCP_COM_PROTO);
        if(cid <= 0) {
            VR_LOG(LOG_ERROR, "Error trying to create new client");
            err = 1;
            goto end;
        }
        
        VR_LOG(LOG_INFO, "Client ID created: %ld", cid);
    }

    r = write(sock, &cid, sizeof(uint32_t));
    if(r <= 0 || r != sizeof(uint32_t)) {
        VR_LOG(LOG_ERROR, "Error trying to send final verdict with client_id: %d", cid);
        err = 1;
        goto end;
    }

    if(cid == 0) {
        VR_LOG(LOG_ERROR, "Handshake is failed by client, cid = 0");
        err = 1;
        goto end;
    }

    err = 0;
end:
    if(p) {
        free(p);
        p = NULL;
    }
    
    if(p_clt) {
        free(p_clt);
        p_clt = NULL;
    }

    if(err) {
        if(cid)
            close_client(cid);
        return 0;
    }

    return cid;
}

int relay_tcp_srv_poll(int sock) {
    int err = 0;
    int cid = 0;
    int res = 0;
    struct pollfd fds[1];
    char *tmp_buffer = NULL;
    size_t tmp_buffer_sz = 0;
    ssize_t rx = 0;
    char *qdata = NULL;
    size_t qsize = 0;
    char *enc = NULL;
    size_t enc_sz = 0;
    char *dec = NULL;
    size_t dec_sz = 0;
    int ref_idx = -1;
  
    if(sock < 0) {
        err = 1;
        goto end;
    }
  
    if(!(cid = handshake(sock))) {
        VR_LOG(LOG_INFO, "Handshake failed for client");
        err = 1;
        goto end;
    }

    fds[0].fd = sock;
    fds[0].events = POLLIN;
  
    while(1) {
        if(tmp_buffer) {
            free(tmp_buffer);
            tmp_buffer = NULL;
        }
        
        if(dec) {
            free(dec);
            dec = NULL;
        }
        
        if(qdata) {
            free(qdata);
            qdata = NULL;
        }
        
        ref_idx = is_route_discovery_in_process(cid);
        
        if(ref_idx >= 0) { // if(!is_client_in_checked_list_by_idx(cid, ref_idx, 0))
            VR_LOG(LOG_DEBUG, "There is a discovery process currently. Testing this node as a possible route...");
            qdata = get_route_req_open_cmd(ref_idx, cid, &qsize);   
            if(!qdata || qsize == 0) {
                VR_LOG(LOG_ERROR, "get_route_req_open_cmd() returned NULL...");
                err = 1;
                goto end;
            }
            
            VR_LOG(LOG_DEBUG, "Encrypting output data...");
            
            enc = encrypt_data(qdata, qsize, _key, _key_sz, &enc_sz);
            if(!enc) {
                VR_LOG(LOG_ERROR, "Error trying to encrypt data");
                err = 1;
                goto end;
            }
            
            VR_LOG(LOG_DEBUG, "Sending packet to client (size=%ld)...", enc_sz);
            
            rx = write_all(sock, &enc, &enc_sz);
            if(rx < 0) {
                VR_LOG(LOG_ERROR, "Error trying to write data");
                err = 1;
                goto end;
            }
            
            if(enc) {
                free(enc);
                enc = NULL;
            }
            
            sleep(1);
            
            continue;
        }
        
        res = poll(fds, 1, POLL_TIMEOUT);
        if(res == -1) {
            if(cid) {
                close_client(cid);
                cid = 0;
            }
            VR_LOG(LOG_ERROR, "Error at poll");
            err = 1;
            goto end;
        } else if(res == 0) {
            continue;
        } else {
            if(fds[0].revents & POLLIN) {
                rx = read_all(sock, &tmp_buffer, &tmp_buffer_sz);
                if(rx < 0) {
                    if(cid) {
                        close_client(cid);
                        cid = 0;
                    }
                    VR_LOG(LOG_ERROR, "Error trying to read data");
                    err = 1;
                    goto end;
                } else if(rx == 0) { /* conn closed */
                    if(cid) {
                        close_client(cid);
                        cid = 0;
                    }
                    err = 0;
                    goto end;
                }
                
                hexdump("encrypted packet", tmp_buffer, tmp_buffer_sz);
                
                dec = decrypt_data(tmp_buffer, tmp_buffer_sz, _key, _key_sz, &dec_sz);
                if(!dec) {
                    err = 1;
                    goto end;
                }
                
                hexdump("decrypted packet", dec, dec_sz);
            
                if(!interpret_remote_packet(cid, dec, dec_sz)) {
                    VR_LOG(LOG_ERROR, "Error trying to interpret received packet");
                    err = 1;
                    goto end;
                }

            } else if((fds[0].revents & POLLHUP) != 0) { /* conn closed */
                if(cid) {
                    close_client(cid);
                    cid = 0;
                }
                err = 0;
                goto end;
            }
        
            sleep(1);
        } 
    }
  
    err = 0;
end:
    if(cid > 0) {
        close_client(cid);
        cid = 0;
    }
    
    if(dec) {
        free(dec);
        dec = NULL;
    }
    
    if(enc) {
        free(enc);
        enc = NULL;
    }
    
    if(qdata) {
        free(qdata);
        qdata = NULL;
    }

    if(tmp_buffer) {
        free(tmp_buffer);
        tmp_buffer = NULL;
    }     
     
    if(sock != -1) {
        close(sock);
        sock = -1;
    }
    return 1;
}

ssize_t http_write_all(int sock, SSL *c_ssl, char **data, size_t *data_sz, int is_https) {
    int r = 0;
    size_t sent = 0;
    char *ptr = NULL;
    size_t sz = 0;

    if(sock < 0 || !data || !data_sz)
        return -1;
        
    if(is_https && !c_ssl)
        return -1;

    if(data && data_sz) {
        ptr = *data;
        sz = *data_sz;
    }
    
    VR_LOG(LOG_DEBUG, "Sending %ld bytes of data...", sz);

    while(sent < sz) {
        if(is_https)
            r = SSL_write(c_ssl, ptr, sz - sent);
        else
            r = write(sock, ptr, sz - sent);
        if(r < 0) {
            VR_LOG(LOG_ERROR, "Error trying to write data");
            return -1;
        }
        sent += r;
    }
    
    VR_LOG(LOG_DEBUG, "%ld bytes of data successfully sent...", sent);

    return sent;
}

ssize_t http_read_all(int sock, SSL *c_ssl, char **data, size_t *data_sz, int is_https) {
    int bytes_available = 0;
    int bavailable_x = 0;
    size_t sent = 0;
    int r = 0;
    int rx = 0;
    char *ptr = NULL;
    int sock_m = -1;
    int tries = 0;
    int max_tries = 20;

    if(sock < 0 || !data || !data_sz)
        return -1;
        
    if(is_https && !c_ssl)
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
    
    while(tries < max_tries) {
        #if WINDOWS_OS
        r = ioctlsocket(sock_m, FIONREAD, &bytes_available);
        #else
        r = ioctl(sock_m, FIONREAD, &bytes_available);
        #endif
        if(r < 0) {
            VR_LOG(LOG_ERROR, "Error at ioctl() with FIONREAD");
            return -1;
        }

        if(bytes_available < 0) {
            *data = NULL;
            *data_sz = 0;
            return 0;
        }
        
        if(bytes_available == 0) {
            VR_LOG(LOG_DEBUG, "No data received, giving a new opportunity (%d/%d)...", tries, max_tries);
        } else {
            break;
        }
        
        sleep(1);
        
        tries++;
    
    }
    
    VR_LOG(LOG_DEBUG, "There are %ld bytes available", bytes_available);

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
            VR_LOG(LOG_ERROR, "Error trying to receive data");
            return -1;
        }

        sent += r;
      
        #if WINDOWS_OS
        rx = ioctlsocket(sock_m, FIONREAD, &bavailable_x);
        #else
        rx = ioctl(sock_m, FIONREAD, &bavailable_x);
        #endif
        if(rx < 0) {
            VR_LOG(LOG_ERROR, "Error at ioctl() with FIONREAD");
            return -1;
        }
    
        if(bavailable_x <= 0)
            break;
    }

    *data = ptr;
    *data_sz = sent;

    return sent;
}

int get_get_param(char *data, size_t data_sz, int is_handshake) {
    char *p = NULL;
    char *keyword = NULL;
    char *p2 = NULL;
    char *p3 = NULL;
    int found = 0;
    int param = 0;
    char *dec_id = NULL;
    size_t dec_id_sz = 0;
    char *b64_dec_id = NULL;
    size_t b64_dec_sz = 0;
    uint32_t rec_id = 0;
	
    if(!data || data_sz == 0 || is_handshake < 0)
        return -1;
	
    if(is_handshake)
        keyword = "?h=";
    else
        keyword = "?cid=";
	
    p = memdup(data, data_sz);
    if(!p) {
        return -1;
    }

    p2 = strstr(p, keyword);
    if(!p2) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Could not find parameter in HTTP request");
        return -1;
    }
    p3 = p2 + strlen(keyword);
           
    found = 0;
    for(int i = 0 ; i < strlen(p3) ; i++) {
        if(p3[i] == ' ') {
            p3[i] = '\0';
            found = 1;
            break;
        } 
    }
           
    if(!found) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Provided request is invalid");
        return -1;
    }
    
    if(p3[strlen(p3) - 1] == 0x0a)
        p3[strlen(p3) - 1] = '\0';
    
    b64_dec_id = (char *)base64_decode((unsigned char *)p3, strlen(p3), &b64_dec_sz);
    if(!b64_dec_id || b64_dec_sz == 0) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to do base64 decoding");
        return -1;
    }
    
    dec_id = decrypt_data(b64_dec_id, b64_dec_sz, _key, _key_sz, &dec_id_sz);
    if(!dec_id || dec_id_sz == 0) {
        if(p) {
            free(p);
            p = NULL;
        }

        if(b64_dec_id) {
            free(b64_dec_id);
            b64_dec_id = NULL;
        }
        
        VR_LOG(LOG_ERROR, "Error trying to decrypt data");
        return -1;
    }
    
    if(dec_id_sz != sizeof(uint32_t)) {
        if(p) {
            free(p);
            p = NULL;
        }

        if(b64_dec_id) {
            free(b64_dec_id);
            b64_dec_id = NULL;
        }

        if(dec_id) {
            free(dec_id);
            dec_id = NULL;
        }
        
        VR_LOG(LOG_ERROR, "Received encrypted ID is NOT the size of uint32_t (4 bytes)");
        
        return -1;
    }
    
    memcpy((char *)&rec_id, dec_id, sizeof(uint32_t));
    
    VR_LOG(LOG_DEBUG, "rec_id: %d", rec_id);
    
    /*   
    param = atoi(p3);
    if(param <= 0) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Received parameter is invalid");
        return -1;
    }
    */
    
    if(rec_id <= 0) {
        if(p) {
            free(p);
            p = NULL;
        }

        if(b64_dec_id) {
            free(b64_dec_id);
            b64_dec_id = NULL;
        }

        if(dec_id) {
            free(dec_id);
            dec_id = NULL;
        }
        
        VR_LOG(LOG_ERROR, "Received param is less than or equal to 0");
        
        return -1;
    }
           
    if(p) {
        free(p);
        p = NULL;
    }
    
    if(b64_dec_id) {
        free(b64_dec_id);
        b64_dec_id = NULL;
    }
        
    if(dec_id) {
        free(dec_id);
        dec_id = NULL;
    }
           
    return rec_id;
}

char *get_data_from_http(char *data, size_t data_sz, size_t *out_size) {
    char *p = NULL;
    char *p2 = NULL;
    char *p3 = NULL;
    char *raw = NULL;
    size_t raw_sz = 0;
   
    if(!data || data_sz == 0 || !out_size)
        return NULL;
     
    *out_size = 0;
    
    p = memdup(data, data_sz);
    if(!p) {
        return NULL;
    }
    
    hexdump("original HTTP request", data, data_sz);
    
    p2 = strstr(p, DATA_INPUT_PREFIX);
    if(!p2) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Could not find HTTP request prefix");
        return NULL;
    }
    p2 += strlen(DATA_INPUT_PREFIX);
   
    p3 = strstr(p2, DATA_INPUT_SUFFIX);
    if(!p3) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Could not find HTTP request suffix");
        return NULL;
    }
   
    *p3 = 0;
    
    if(p2[strlen(p2) - 1] == 0x0a)
        p2[strlen(p2) - 1] = '\0';
 
    raw = (char *)base64_decode((unsigned char *)p2, strlen(p2), &raw_sz);
    if(!raw) {
        if(p) {
            free(p);
            p = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to do base64 decoding");
        return NULL;
    }
  
    if(p) {
        free(p);
        p = NULL;
    }

    *out_size = raw_sz;

    return raw;
}

char *get_http_data_response(char *data, size_t data_sz, size_t *out_size) {
    char *out = NULL;
    size_t osz = 0;
    char *b64_p = NULL;
    size_t b64_sz = 0;
    char *raw_d = NULL;
    size_t raw_sz = 0;
  
    if(!data || data_sz == 0 || !out_size)
        return NULL;
    
    *out_size = 0;
    
    raw_sz = data_sz + PNG_FAKE_HDR_SIZE;
    raw_d = calloc(raw_sz, sizeof(char));
    if(!raw_d) {
        *out_size = 0;
        return NULL;
    }
    
    memcpy(raw_d, PNG_FAKE_HDR, PNG_FAKE_HDR_SIZE);
    memcpy(raw_d + PNG_FAKE_HDR_SIZE, data, data_sz);
  
    b64_p = (char *)base64_encode((unsigned char *)raw_d, raw_sz, &b64_sz);
    if(!b64_p || b64_sz == 0) {
        VR_LOG(LOG_ERROR, "Error trying to do base64 encoding");
        *out_size = 0;
        return NULL;
    }

    if(b64_p[strlen(b64_p) - 1] == 0x0a)
        b64_p[strlen(b64_p) - 1] = '\0';
        
    if(raw_d) {
        free(raw_d);
        raw_d = NULL;
    }
  
    asprintf(&out, "HTTP/1.1 200 OK\r\n"
             "Cache-Control: private, max-age=0\r\n"
             "Content-Type: text/html; charset=ISO-8859-1\r\n"
             "X-XSS-Protection: 0\r\n"
             "X-Frame-Options: SAMEORIGIN\r\n"
	     "Set-Cookie: session=jnd82Nsb2VFDJdn25sAlF6sdD47wv\r\n"
	     "Content-Length: %ld\r\n"
	     "\r\n<!DOCTYPE html><html><head><title>image</title></head><body>%s%s%s</body></html>",
	      strlen(DATA_PREFIX) + strlen(b64_p) + strlen(DATA_SUFFIX) + 74, DATA_PREFIX, b64_p, DATA_SUFFIX);
    osz = strlen(out);
  
    if(b64_p) {
        free(b64_p);
        b64_p = NULL;
    }
    
    *out_size = osz;
    return out;
}

/*
int is_client_in_checked_list(int client_id) {
    int found = 0;
    
    if(client_id <= 0)
        return 0;
        
    if(!conn_req_glb)
        return 0;
        
    pthread_mutex_lock(&conn_req_lock);
    
    if(conn_req_glb->is_routed == 1) {
        pthread_mutex_unlock(&conn_req_lock);
        return 1; // pretend its already there to prevent scanning
    }

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(conn_req_glb->client_id_arr[i] == client_id) {
            found = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(&conn_req_lock);
    return found;
}
*/

int is_client_in_checked_list_by_idx(int client_id, int idx, int internal) {
    int found = 0;
    
    if(client_id <= 0 || idx < 0)
        return 0;
        
    if(internal != 1 && internal != 0)
        return 0;
        
    if(!conn_req_glb)
        return 0;
    
    if(!internal)
        pthread_mutex_lock(&conn_req_lock);
    
    if(conn_req_glb[idx].is_routed == 1) {
        if(!internal)
            pthread_mutex_unlock(&conn_req_lock);
        return 1; /* pretend its already there to prevent scanning */
    }

    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(conn_req_glb[idx].client_id_arr[i] == client_id) {
            found = 1;
            break;
        }
    }
    
    if(!internal)
        pthread_mutex_unlock(&conn_req_lock);
    
    return found;
}

int mark_route_found(int client_id, int channel_id, int found) {
    int idx = -1;
    int c_idx = -1;
    
    if(client_id <= 0 || channel_id <= 0 || found < 0)
        return 0;
        
    if(!conn_req_glb)
        return 0;
        
    pthread_mutex_lock(&conn_req_lock);
    
    for(int i = 0 ; i < MAX_CONCURRENT_CONN_OPEN ; i++) {
        if(conn_req_glb[i].channel_id == channel_id) {
            c_idx = i;
            break;
        }
    }
    
    if(c_idx == -1) {
        VR_LOG(LOG_ERROR, "Provided channel ID %d was not found", channel_id);
        pthread_mutex_unlock(&conn_req_lock);
        return 0;
    }
    
    if(!found) {
        for(int x = 0 ; x < MAX_CONCURRENT_CLIENTS ; x++) {
            if(conn_req_glb[c_idx].client_id_arr[x] == 0) {
                idx = x;
                break;
            }
        }

        if(idx == -1) {
            VR_LOG(LOG_ERROR, "No left space in conn_req_glb[%d].client_id_arr...", c_idx);
            pthread_mutex_unlock(&conn_req_lock);
            return 0;
        }
    
        conn_req_glb[c_idx].client_id_arr[idx] = client_id;
        
        pthread_mutex_unlock(&conn_req_lock);
        return 1;
    }
    
    conn_req_glb[c_idx].is_routed = 1;
    conn_req_glb[c_idx].client_id = client_id;
    
    pthread_mutex_unlock(&conn_req_lock);
    return 1;
}

int is_route_solved(int channel_id) {
    int idx = -1;
    
    if(channel_id < 0)
        return 1; /* consider it as yes to skip errors */
        
    pthread_mutex_lock(&conn_req_lock);
        
    for(int i = 0 ; i < MAX_CONCURRENT_CONN_OPEN ; i++) {
        if(conn_req_glb[i].channel_id == channel_id) {
            idx = i;
            break;
        }
    } 

    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Provided channel ID %d was not found", channel_id);
        pthread_mutex_unlock(&conn_req_lock);
        return 1; /* consider it as yes to skip errors */
    }
    
    if(conn_req_glb[idx].is_routed == 1) {
        pthread_mutex_unlock(&conn_req_lock);
        return 1;
    }
    
    pthread_mutex_unlock(&conn_req_lock);
        
    return 0;
}

int is_route_discovery_in_process(int client_id) {
    int idx = -1;
    
    if(client_id < 0)
        return -1;
    
    if(!conn_req_glb)
        return -1;
    
    pthread_mutex_lock(&conn_req_lock);
    
    for(int i = 0 ; i < MAX_CONCURRENT_CONN_OPEN ; i++) {
        if(conn_req_glb[i].in_use == 1 && conn_req_glb[i].is_routed == 0
               && conn_req_glb[i].ip != 0 && conn_req_glb[i].port != 0) {
            
            if(is_client_in_checked_list_by_idx(client_id, i, 1))
                continue;
                
            idx = i;
            break;
        }
    }
    
    if(idx == -1) {
        pthread_mutex_unlock(&conn_req_lock);
        return -1;
    }
    
    pthread_mutex_unlock(&conn_req_lock);
    
    return idx; 
}

char *get_route_req_open_cmd(int idx, int client_id, size_t *out_size) {
    size_t osz = 0;
    char *p = NULL;
    tlv_header *tlv = NULL;
    conn_cmd *c_cmd = NULL;
    int c_idx = -1;
    
    if(idx < 0 || client_id <= 0 || !out_size)
        return NULL;
    
    *out_size = 0;
    
    if(!conn_req_glb)
        return NULL;
    
    pthread_mutex_lock(&conn_req_lock);
    
    if(conn_req_glb[idx].is_routed == 1) {
        pthread_mutex_unlock(&conn_req_lock);
        return NULL;
    }
    
    if(conn_req_glb[idx].ip == 0 || conn_req_glb[idx].port == 0) {
        pthread_mutex_unlock(&conn_req_lock);
        return NULL;
    }
    
    osz = sizeof(tlv_header) + sizeof(conn_cmd);
    p = calloc(osz, sizeof(char));
    if(!p) {
        pthread_mutex_unlock(&conn_req_lock);
        return NULL;
    }
    
    tlv = (tlv_header *)p;
    c_cmd = (conn_cmd *)((char *)p + sizeof(tlv_header));
    
    tlv->client_id = client_id;
    tlv->channel_id = COMMAND_CHANNEL;
    tlv->tlv_data_len = sizeof(conn_cmd);
    
    c_cmd->cmd = cmd_def_data[CHANNEL_OPEN_CMD].value;
    c_cmd->channel_id = conn_req_glb[idx].channel_id;
    c_cmd->ip_addr = htonl(conn_req_glb[idx].ip);
    c_cmd->port = conn_req_glb[idx].port;
    
    for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
        if(conn_req_glb[idx].client_id_arr[i] == 0) {
            c_idx = i;
            break;
        }
    }
    
    if(c_idx == -1) {
        VR_LOG(LOG_ERROR, "No space left in conn_req_glb[%d].client_id_arr, MAX_CONCURRENT_CLIENTS reached", idx);
        *out_size = 0;
        pthread_mutex_unlock(&conn_req_lock);
        return NULL;
    }
    
    conn_req_glb[idx].client_id_arr[c_idx] = client_id;
    
    pthread_mutex_unlock(&conn_req_lock);
    
    *out_size = osz;
    return p; 
}

int create_conn_req_entry(int channel_id, uint32_t ip_addr, uint16_t port) {
    int idx = -1;
    
    if(channel_id <= 0 || ip_addr == 0 || port == 0) {
        VR_LOG(LOG_ERROR, "Invalid values passed, this may lead to infinite loop...");
        return -1;
    }
    
    if(!conn_req_glb) {
        VR_LOG(LOG_ERROR, "conn_req_glb is NULL, this may lead to infinite loop...");
        return -1;
    }
    
    pthread_mutex_lock(&conn_req_lock);
    
    for(int i = 0 ; i < MAX_CONCURRENT_CONN_OPEN ; i++) {
        if(conn_req_glb && conn_req_glb[i].in_use == 0) {
            idx = i;
            break;
        }
    }
    
    if(idx == -1) {
        VR_LOG(LOG_INFO, "Maximum simultaneous route discovery requests reached");
        pthread_mutex_unlock(&conn_req_lock);
        return -1;
    }

    conn_req_glb[idx].in_use = 1;
    conn_req_glb[idx].is_routed = 0;
    conn_req_glb[idx].channel_id = channel_id; /* temporal channel id for ref */
    conn_req_glb[idx].client_id = 0;
    conn_req_glb[idx].ip = ip_addr;
    conn_req_glb[idx].port = port;
    
    for(int x = 0 ; x < MAX_CONCURRENT_CLIENTS ; x++)
        conn_req_glb[idx].client_id_arr[x] = 0;
    
    pthread_mutex_unlock(&conn_req_lock);
    
    return idx;
}

/* XXX: locking relies on caller */
int delete_conn_entry_by_id(int idx) {
    if(idx < 0)
        return 0;
        
    if(!conn_req_glb)
        return 0;

    conn_req_glb[idx].in_use = 0;
    conn_req_glb[idx].is_routed = 0;
    conn_req_glb[idx].channel_id = 0;
    conn_req_glb[idx].client_id = 0;
    conn_req_glb[idx].ip = 0;
    conn_req_glb[idx].port = 0;
    
    for(int x = 0 ; x < MAX_CONCURRENT_CLIENTS ; x++)
        conn_req_glb[idx].client_id_arr[x] = 0;
        
    return 1;
}

int delete_conn_entry(int channel_id) {
    int idx = -1;
    
    if(channel_id <= 0)
        return 0;
        
    if(!conn_req_glb)
        return 0;
        
    pthread_mutex_lock(&conn_req_lock);
       
    for(int i = 0 ; i < MAX_CONCURRENT_CONN_OPEN ; i++) {
        if(conn_req_glb && conn_req_glb[i].channel_id == 0) {
            idx = i;
            break;
        }
    }
    
    if(idx == -1) {
        VR_LOG(LOG_ERROR, "Entry for channel ID '%d' was not found in connection open request defs...", channel_id);
        pthread_mutex_unlock(&conn_req_lock);
        return 0;
    }
    
    if(!delete_conn_entry_by_id(idx)) {
        pthread_mutex_unlock(&conn_req_lock);
        return 0;
    }
        
    pthread_mutex_unlock(&conn_req_lock);
    
    return 1;
}

int issue_connection_open(int proxy_sock, uint32_t ip_addr, uint16_t port) {
    int channel_id = 0;
    int err = 0;
    int success = 0;
    int client_id = 0;
    int c_id = 0;
    char *host = NULL;
    time_t route_req_init_time = 0;
    time_t curr_time = 0;
    struct in_addr i_addr;
    int idx = -1;
    
    if(ip_addr == 0 || port == 0)
        return 0;
    
    channel_id = generate_channel_id();
    
    idx = -1;
    while(idx == -1) {
        idx = create_conn_req_entry(channel_id, ip_addr, port);
        sleep(1);
    }
    
    route_req_init_time = time(NULL);
    
    VR_LOG(LOG_DEBUG, "Starting connection open request main loop (id=%d)...", idx);
    
    while(1) {
        curr_time = time(NULL);
        
        VR_LOG(LOG_INFO, "Applying algorithm for route discovery (id=%d)...", idx);
        
        if((curr_time - route_req_init_time) >= ROUTE_REQUEST_PROCESS_TIMEOUT) {
            VR_LOG(LOG_INFO, "Timed out tring to open a new connection (id=%d)...", idx);
            success = 0;
            break;
        }
        
        if(conn_req_glb[idx].is_routed && conn_req_glb[idx].client_id != 0) {
            VR_LOG(LOG_INFO, "Discovery process finished, route discovered successfully (idx=%d)...", idx);
            success = 1;
            client_id = conn_req_glb[idx].client_id;
            break;
        }
        
        sleep(1);
    }
    
    pthread_mutex_lock(&conn_req_lock);
            
    if(!delete_conn_entry_by_id(idx)) {
        VR_LOG(LOG_ERROR, "Could not remove connection open request global def entry...");
        success = 0;
    }
            
    pthread_mutex_unlock(&conn_req_lock);
    
    if(!success) {
        err = 1;
        goto end;
    }
    
    i_addr.s_addr = ip_addr;
    host = inet_ntoa(i_addr);
    if(!host) {
        VR_LOG(LOG_ERROR, "Error at inet_ntoa");
        err = 1;
        goto end;
    }
    
    VR_LOG(LOG_DEBUG, "Creating a new channel for channel_id: %ld", channel_id);
    
    c_id = create_channel_custom(channel_id, client_id, proxy_sock, host, port);
    if(c_id <= 0 || c_id != channel_id) {
        VR_LOG(LOG_ERROR, "Error trying to create a channel");
        err = 1;
        goto end;
    }
    
    err = 0;
end:
    if(err)
        channel_id = 0;

    return channel_id;
}

char *interpret_http_req(char *data, size_t data_sz, size_t *out_size) {
    char *p1 = NULL;
    char *p2 = NULL;
    char *p3 = NULL;
    char *chall = NULL;
    char *real_sol = NULL;
    size_t real_sol_sz = 0;
    int cid = 0;
    int h_id = 0;
    int err = 0;
    char *out = NULL;
    size_t osz = 0;
    char *raw = NULL;
    size_t raw_sz = 0;
    int param = 0;
    char *enc = NULL;
    size_t enc_sz = 0;
    char *qdata = NULL;
    size_t qsize = 0;
    int ref_idx = -1;
    req_t req_type = UNKNOWN_REQUEST_TYPE;
   
    if(!data || data_sz == 0 || !out_size)
        return NULL;
      
    *out_size = 0;
  
    p1 = strstr(data, "?h=");
    if(p1) {
        req_type = HANDSHAKE_SESSION_TYPE;
    } else if (p2 = strstr(data, "?cid=")) {
        if(p3 = strstr(data, "Content-Length: 0\r\n")) {
            req_type = DATA_REQUEST_TYPE;
        } else {
            req_type = DATA_SENDING_TYPE;
        }
    } else {
      req_type = UNKNOWN_REQUEST_TYPE;
    }
   
    p1 = NULL;
    p2 = NULL;
    p3 = NULL;
   
    if(req_type == UNKNOWN_REQUEST_TYPE) {
        VR_LOG(LOG_ERROR, "Unknown request type");
        *out_size = 0;
        return NULL;
    }
   
    param = get_get_param(data, data_sz, (req_type == HANDSHAKE_SESSION_TYPE) ? 1 : 0);
    if(param <= 0) {
        VR_LOG(LOG_ERROR, "Error trying to get parameter");
        *out_size = 0;
        goto end;
    }
   
    if(req_type == DATA_SENDING_TYPE ||
            req_type == DATA_REQUEST_TYPE) {
        cid = param;
        
        if(!client_exists(cid)) {
            VR_LOG(LOG_ERROR, "HTTP request 'cid' parameter contains an non-existing client ID");
            err = 1;
            goto end;
        }
        
        if(req_type == DATA_SENDING_TYPE) {
            VR_LOG(LOG_DEBUG, "Client sending data to the server...");
            
            enc = get_data_from_http(data, data_sz, &enc_sz);
            if(!enc || enc_sz == 0) {
                VR_LOG(LOG_ERROR, "Error trying to get data from HTTP request");
                err = 1;
                goto end;
            }

            raw = decrypt_data(enc, enc_sz, _key, _key_sz, &raw_sz);
            if(!raw || raw_sz == 0) {
                VR_LOG(LOG_ERROR, "Error trying to decrypt data");
                err = 1;
                goto end;
            }
		   
            VR_LOG(LOG_DEBUG, "Received a total of %ld raw data bytes from client...", raw_sz);
            
            if(!interpret_remote_packet(cid, raw, raw_sz)) {
                VR_LOG(LOG_ERROR, "Error trying to interpret remote packet");
                err = 1;
                goto end;
            }

            if(raw) {
                free(raw);
                raw = NULL;
            }
		 
            *out_size = 0;
            return NULL;
        } else if(req_type == DATA_REQUEST_TYPE) {
            VR_LOG(LOG_DEBUG, "Client is asking for data to be returned...");
            
            // TODO: should we add more locking here to ensure concurrency issues on multiple clients at once?
            VR_LOG(LOG_DEBUG, "Data requested by client...");
            
            ref_idx = is_route_discovery_in_process(cid);

            if(ref_idx >= 0) { // if(!is_client_in_checked_list_by_idx(cid, ref_idx, 0))
                VR_LOG(LOG_DEBUG, "There is a discovery process currently. Testing this node as a possible route...");
                qdata = get_route_req_open_cmd(ref_idx, cid, &qsize);    
            } else {
                VR_LOG(LOG_DEBUG, "Trying to retrieve queued data...");
                qdata = get_next_queued_data(cid, &qsize);
            }
            
            if(!qdata || qsize == 0) {
                VR_LOG(LOG_WARN, "No data to be returned. Dummy response...");
                *out_size = 0;
                return NULL;
            }
            
            VR_LOG(LOG_DEBUG, "Returning to client %ld bytes in total...", qsize);
	    
	    VR_LOG(LOG_DEBUG, "Encrypting output data...");
	    
            enc = encrypt_data(qdata, qsize, _key, _key_sz, &enc_sz);
            if(!enc) {
                if(qdata) {
                    free(qdata);
                    qdata = NULL;
                }
                VR_LOG(LOG_ERROR, "Error trying to encrypt data");
                *out_size = 0;
                return NULL;
            }
	   	   
            if(qdata) {
                free(qdata);
                qdata = NULL;
            }
	   	   
            out = get_http_data_response(enc, enc_sz, &osz);
            if(!out || osz == 0) {
                if(enc) {
                    free(enc);
                    enc = NULL;
                }
                VR_LOG(LOG_ERROR, "Error trying to craft a valid HTTP response");
                err = 1;
                goto end;
            }
                   
            if(enc) {
                free(enc);
                enc = NULL;
            }
        }
    } else if(req_type == HANDSHAKE_SESSION_TYPE) {
        VR_LOG(LOG_DEBUG, "Client request is handshake-related...");
        
        h_id = param;
        if(handshake_sess_exists(h_id)) {
            if(is_challenge_solved(h_id) || is_challenge_failure(h_id)) {
                if(is_challenge_solved(h_id)) {
                    VR_LOG(LOG_DEBUG, "Challenge is solved, creating client global def...");
                    
                    cid = create_client(-1, NULL, 0, _proto);
                    if(cid <= 0) {
                        VR_LOG(LOG_ERROR, "Error trying to create a new client");
                        err = 1;
                        goto end;
                    }
                    
                    VR_LOG(LOG_INFO, "Created client ID for new relay session: %d", cid);
                } else if (is_challenge_failure(h_id)) {
                    cid = 0;
                } else {
                    VR_LOG(LOG_ERROR, "Unknown error");
                    err = 1;
                    goto end;
                }
        
                out = get_http_data_response((char *)&cid, sizeof(uint32_t), &osz);
                if(!out || osz == 0) {
                    VR_LOG(LOG_ERROR, "Error when trying to craft a valid HTTP response (2)");
                    err = 1;
                    goto end;
                }
                err = 0;
                goto end;
            } else {
                VR_LOG(LOG_DEBUG, "Getting HTTP request data...");
                
                raw = get_data_from_http(data, data_sz, &raw_sz);
                if(!raw || raw_sz == 0) {
                    VR_LOG(LOG_ERROR, "Error trying to get raw data");
                    err = 1;
                    goto end;
                }
		
		VR_LOG(LOG_DEBUG, "Retrieving original challenge solution...");
		
                real_sol = get_h_challenge_solution(h_id, &real_sol_sz);
                if(!real_sol) {
                    VR_LOG(LOG_ERROR, "Error trying to get the challenge saved solution");
                    err = 1;
                    goto end;
                }
                
                VR_LOG(LOG_DEBUG, "Checking client solution...");
		  
                if(raw_sz == real_sol_sz && (memcmp(raw, real_sol, raw_sz) == 0)) {
                    VR_LOG(LOG_INFO, "Challenge solution provided by client is correct");
                    if(!mark_challenge_solved(h_id)) {
                        VR_LOG(LOG_ERROR, "Error trying to mark challenge as solved");
                        err = 1;
                        goto end;
                    }
                } else {
                    VR_LOG(LOG_INFO, "Challenge solution provided by client is wrong");
                    if(!mark_challenge_failure(h_id)) {
                        VR_LOG(LOG_ERROR, "Error trying to mark challenge as failed to solve");
                        err = 1;
                        goto end;
                    }
                }

                if(raw) {
                    free(raw);
                    raw = NULL;
                }
                *out_size = 0;
                return NULL;
            }
        } else {
            VR_LOG(LOG_DEBUG, "Creating handshake global def...");
            
            if(!create_handshake(h_id)) {
                VR_LOG(LOG_ERROR, "Error trying to create handshake");
                err = 1;
                goto end;
            }
            
            VR_LOG(LOG_DEBUG, "Retrieving challenge...");
             
            chall = get_challenge(h_id);
            if(!chall) {
                VR_LOG(LOG_ERROR, "Error trying to get challenge");
                err = 1;
                goto end;
            }
            
            VR_LOG(LOG_DEBUG, "Crafting HTTP response with challenge...");
             
            out = get_http_data_response(chall, CHALLENGE_DEFAULT_SIZE, &osz);
            if(!out || osz == 0) {
                VR_LOG(LOG_ERROR, "Error trying to craft a valid HTTP response (3)");
                err = 1;
                goto end;
            }
            
            hexdump("HTTP response", out, osz);
             
            err = 0;
            goto end;
        }
    }
      
    err = 0;
end:
    if(raw) {
        free(raw);
        raw = NULL;
    }
   
    if(!err) {
        *out_size = osz;
        return out;
    }
   
    *out_size = 0;
    return NULL;
}

int relay_http_srv_handle_req(rl_arg_pass *arg) {
    int err = 0;
    int is_https = 0;
    char *out = NULL;
    size_t out_size = 0;
    char *data = NULL;
    size_t data_sz = 0;
    ssize_t r = 0;
    int sock = 0;
    SSL *c_ssl = NULL;
  
    if(!arg) {
        err = 1;
        goto end;
    }
  
    is_https = arg->is_https;
    sock = arg->sock;
    c_ssl = arg->c_ssl;
  
    if(!is_https && sock < 0) {
        err = 1;
        goto end;
    }
  
    if(is_https && !c_ssl) {
        err = 1;
        goto end;
    }
  
    r = http_read_all(sock, c_ssl, &data, &data_sz, is_https);
    if(r < 0) {
        VR_LOG(LOG_ERROR, "Error trying to read HTTP request");
        err = 1;
        goto end;
    }
  
    if(!data || data_sz == 0) {
        err = 0;
        goto end;
    }
    
    VR_LOG(LOG_DEBUG, "Received %ld bytes from client...", data_sz);

    out = interpret_http_req(data, data_sz, &out_size);
    if(!out || out_size == 0) {
        asprintf(&out, "HTTP/1.1 200 OK\r\n"
                     "Cache-Control: private, max-age=0\r\n"
                     "Content-Type: text/html; charset=ISO-8859-1\r\n"
                     "X-XSS-Protection: 0\r\n"
                     "X-Frame-Options: SAMEORIGIN\r\n"
      		     "Set-Cookie: session=jnd82Nsb2VFDJdn25sAlF6sdD47wv\r\n"
      		     "Content-Length: 78\r\n"
      		     "\r\n%s", "<!DOCTYPE html><html><head><title>blank</title></head><body><h1>blank page</h1></body></html>");
        out_size = strlen(out);
    }
    
    VR_LOG(LOG_DEBUG, "Sending %ld bytes to client...", out_size);
   
    r = http_write_all(sock, c_ssl, &out, &out_size, is_https);
    if(r < 0) {
        VR_LOG(LOG_ERROR, "Error trying to send HTTP response");
        err = 1;
        goto end;
    }
  
    err = 0;
end:
    if(c_ssl) {
        SSL_shutdown(c_ssl);
        SSL_free(c_ssl);
        c_ssl = NULL;
    }
  
    if(sock != -1) {
        close(sock);
        sock = -1;
    }
  
    if(data) {
        free(data);
        data = NULL;
    }
  
    if(out) {
        free(out);
        out = NULL;
    }

    if(arg) {
        free(arg);
        arg = NULL;
    }

    return (err == 0);
}

void proxy_srv_poll(int sock) {
    int err = 0;
    char *rhost = NULL;
    int rport = 0;
    int r = 0;
    int res = 0;
    char socks_hdr_buf[sizeof(socks_hdr) + 1] = { 0 };
    struct pollfd fds[1];
    int client_id = 0;
    int channel_id = 0;
    char *p = NULL;
    size_t p_sz = 0;
    int rsock = 0;
    ssize_t rx = 0;
    int proxy_client_id = 0;
    uint32_t ip_addr_i = 0;
    uint16_t port = 0;
    struct in_addr ip_addr;
    char *enc = NULL;
    size_t enc_sz = 0;
    int no_ccleanup = 0;
    char *rdata = NULL;
    size_t rdata_sz = 0;
   
    if(sock < 0) {
        err = 1;
        goto end;
    }
   
    r = read(sock, socks_hdr_buf, sizeof(socks_hdr));
    if(r < 0) {
        VR_LOG(LOG_ERROR, "Error when reading SOCKS header from proxy client");
        err = 1;
        goto end;
    }
   
    if(r != sizeof(socks_hdr)) {
        VR_LOG(LOG_ERROR, "Received number of bytes does NOT correspond to the size of a SOCKS header");
        err = 1;
        goto end;
    }
   
    if(!parse_socks_hdr((char *)socks_hdr_buf, sizeof(socks_hdr), &rhost, &rport)) {
        VR_LOG(LOG_ERROR, "Error when parsing SOCKS header provided by proxy client");
        err = 1;
        goto end;
    }
   
    if(!rhost || rport <= 0) {
        VR_LOG(LOG_ERROR, "Proxy client provided wrong host or port values...");
        err = 1;
        goto end;
    }

    VR_LOG(LOG_INFO, "Connection target is: %s:%d", rhost, rport);

    if(inet_pton(AF_INET, rhost, &ip_addr) == 0) {
        VR_LOG(LOG_ERROR, "Error at inet_pron()");
        err = 1;
        goto end;
    }
    
    ip_addr_i = ntohl(ip_addr.s_addr);
    
    port = (int16_t)rport;
    
    VR_LOG(LOG_DEBUG, "Issuing connection open request for %s:%d...", rhost, rport);
    
    channel_id = issue_connection_open(sock, ip_addr_i, port);
    if(channel_id <= 0) {
        r = write(sock, SOCKS_REPLY_FAILURE, 8);
        if(r < 0) {
           VR_LOG(LOG_ERROR, "Error when replying to SOCKS proxy client");
           err = 1;
           goto end;
        }
        err = 1;
        goto end;
    } else {
        r = write(sock, SOCKS_REPLY_SUCCESS, 8);
        if(r < 0) {
           VR_LOG(LOG_ERROR, "Error when replying to SOCKS proxy client");
           err = 1;
           goto end;
        }
    }
    
    VR_LOG(LOG_DEBUG, "Creating proxy client definition...");

    proxy_client_id = create_proxy_client(sock, NULL, 0, channel_id);
    if(proxy_client_id <= 0) {
        VR_LOG(LOG_ERROR, "Error when creating a new proxy client definition");
        err = 1;
        goto end;
    }
    
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    
    VR_LOG(LOG_DEBUG, "Starting proxy srv main polling loop...");
  
    while(1) {
        if(!channel_exists(channel_id)) {
            VR_LOG(LOG_INFO, "Channel ID not anymore registered, closing connection poll...");
            no_ccleanup = 1;
            close(sock);
            err = 0;
            goto end;
        }
     
        res = poll(fds, 1, POLL_TIMEOUT);
        if(res == -1) {
            VR_LOG(LOG_ERROR, "Error at poll");
            err = 1;
            goto end;
        } else if(res == 0) {
            continue;
        } else {
            if(fds[0].revents & POLLIN) {
                rx = read_all(sock, &rdata, &rdata_sz);
                if(rx < 0) {
                    VR_LOG(LOG_ERROR, "Error when receiving data from SOCKS proxy client");
                    err = 1;
                    goto end;
                } else if(rx == 0) { /* conn closed */
                    VR_LOG(LOG_INFO, "Connection closed, exiting from connection poll...");
                    err = 0;
                    goto end;
                }
                
                VR_LOG(LOG_DEBUG, "Received %d bytes from SOCKS proxy client...", r);
                
                hexdump("proxy client received data", rdata, rdata_sz);
            
                p = pack_proxy_data(channel_id, rdata, rdata_sz, &p_sz);
                if(!p) {
                    VR_LOG(LOG_ERROR, "Error trying to pack raw data into tlv_header");
                    err = 1;
                    goto end;
                }

                client_id = get_client_by_channel_id(channel_id);
                if(client_id <= 0) {
                    VR_LOG(LOG_ERROR, "Error when trying to get client_id from channel_id: %d", channel_id);
                    err = 1;
                    goto end;
                }
                
                VR_LOG(LOG_DEBUG, "Client to send data to has client ID: %d", client_id);
               
                if(_proto == TCP_COM_PROTO) {
                    rsock = get_relay_sock_by_client_id(client_id);
                    if(rsock < 0) {
                        VR_LOG(LOG_ERROR, "Error when trying to get sock from client_id: %d", client_id);
                        err = 1;
                        goto end;
                    }
                    
                    VR_LOG(LOG_DEBUG, "TCP relay client sock: %d", rsock);
                    
                    enc = encrypt_data(p, p_sz, _key, _key_sz, &enc_sz);
                    if(!enc) {
                        VR_LOG(LOG_ERROR, "Error when trying to encrypt data");
                        err = 1;
                        goto end;
                    }
                    
                    VR_LOG(LOG_DEBUG, "Relaying %d bytes of data to TCP relay client", enc_sz);

                    rx = write_all(rsock, &enc, &enc_sz);
                    if(rx < 0) {
                        VR_LOG(LOG_ERROR, "Error when trying to send data to client");
                        err = 1;
                        goto end;
                    }
                    
                    if(enc) {
                        free(enc);
                        enc = NULL;
                    }
                } else if(_proto == HTTP_COM_PROTO || 
                                _proto == HTTPS_COM_PROTO) {
                    VR_LOG(LOG_DEBUG, "Queuing %d bytes of data...", p_sz);
                    if(!queue_data(client_id, p, p_sz, time(NULL))) {
                        VR_LOG(LOG_ERROR, "Error when trying to queue data");
                        err = 1;
                        goto end;
                    }
                }
            
                if(p) {
                    free(p);
                    p = NULL;
                }
            
            } else if((fds[0].revents & POLLHUP) != 0) { /* conn closed */
                VR_LOG(LOG_INFO, "Connection closed, exiting from connection poll (1)...");
                err = 0;
                goto end;
            }
        
            sleep(1);
        }
    }
    
    err = 0;
end:
    VR_LOG(LOG_INFO, "Finishing proxy server poll. Cleaning up...");
    
    if(!no_ccleanup && channel_id != 0 && !send_remote_cmd(CHANNEL_CLOSE_CMD, channel_id)) {
        VR_LOG(LOG_ERROR, "Error sending CHANNEL_CLOSE_CMD to the remote end with channel ID: %d", channel_id);
        err = 1;
    }
    
    if(proxy_client_id != 0)
        close_proxy_client(proxy_client_id);
    
    if(channel_id != 0) {
        close_channel(channel_id, 0);
        channel_id = 0;
    }
    
    if(sock != -1) {
       close(sock);
       sock = -1;
    }
    
    pthread_exit(NULL);
    return;
}

void start_proxy_srv(arg_pass *arg) {
    char *proxy_host = NULL;
    int proxy_port = 0;
    struct sockaddr_in servaddr;
    int sfd = 0;
    int err = 0;
    int res = 0;
    int i = 0;
    int connfd = 0;
    int z = 0;
    int addrlen = 0;
    pthread_t tid[MAX_CONCURRENT_PROXY_CLIENTS] = { 0 };
  
    if(!arg) {
        err = 1;
        goto end;
    }
     
    proxy_host = arg->host;
    proxy_port = arg->port;

    if(!proxy_host || proxy_port <= 0) {
        err = 1;
        goto end;
    }
     
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sfd < 0) {
        VR_LOG(LOG_ERROR, "Error creating socket");
        err = 1;
        goto end;
    }
   
    bzero(&servaddr, sizeof(servaddr));
  
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(proxy_port);
  
    if((bind(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        VR_LOG(LOG_ERROR, "Error binding socket");
        err = 1;
        goto end;
    }
  
    if((listen(sfd, MAX_CONCURRENT_PROXY_CLIENTS)) != 0) {
        VR_LOG(LOG_ERROR, "Error trying to listen on socket");
        err = 1;
        goto end;
    }
  /*
   on some systems pthread_t is an unsigned long, on other is a pointer to a structure,
   do this method in accordance with both schemes
  */
    i = 0;
    while(1) {
        if(close_srv) {
            VR_LOG(LOG_INFO, "Order to shutdown the server. Closing...");
            goto end;
        }
     
        if(i >= MAX_CONCURRENT_PROXY_CLIENTS) {
            for(int x = 0 ; x < MAX_CONCURRENT_PROXY_CLIENTS ; x++) {
                if(tid[x] == 0)
                    continue;
                    
                res = pthread_kill(tid[x], 0);
                if(res == 0)
                    continue;
                else if(res == ESRCH) {
                    tid[x] = 0;
                    i--;
                } else {
                    VR_LOG(LOG_ERROR, "Error checking thread status");
                    continue; /* err checking status */
                }
            }
             
        }
     
    addrlen = sizeof(servaddr);
    connfd = accept(sfd, (struct sockaddr *)&servaddr, (socklen_t *)&addrlen);
    if(connfd < 0) {
        VR_LOG(LOG_ERROR, "Failed accepting connection");
        continue;
    }
     
    VR_LOG(LOG_INFO, "Client connected to SOCKS proxy server...");
     
    z = 0;
    while(z < MAX_CONCURRENT_PROXY_CLIENTS) {
        if(tid[z] == 0)
            break;
        z++;
    }
     
    if(z == -1) {
        VR_LOG(LOG_ERROR, "Could not find a free spot. MAX_CONCURRENT_PROXY_CLIENTS reached...");
        continue;
    }
     
    if(pthread_create(&tid[z], NULL, (void *)proxy_srv_poll, ((void *)(uint64_t)connfd))) {
        VR_LOG(LOG_ERROR, "Error creating thread");
        continue;
    }
     
    i++;
  }
  
    err = 0;
end:
    z = 0;
    while(z < MAX_CONCURRENT_PROXY_CLIENTS) {
        if(tid[z] == 0) {
            z++;
            continue;
        }
            
        res = pthread_cancel(tid[z]);
        if(res != 0) {
            VR_LOG(LOG_ERROR, "Error trying to cancel thread");
            z++;
            continue;
        }
        z++;
    }
  
    if(arg) {
        free(arg);
        arg = NULL;
    }
  
    if(err) {
        close_srv = 1;
        sleep(2);
    }
    
    close_srv = 1;

    pthread_exit(NULL);
    return;
}

void ssl_initialization(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return;
}

void ssl_cleanup(void) {
    if(_ctx) {
        SSL_CTX_free(_ctx);
        _ctx = NULL;
    }
    return;
}

int do_http_relay_srv(char *host, int port) {
    struct sockaddr_in servaddr;
    int sfd = 0;
    int err = 0;
    int res = 0;
    int i = 0;
    int connfd = 0;
    int z = 0;
    int addrlen = 0;
    pthread_t tid[MAX_CONCURRENT_CLIENTS] = { 0 };
    rl_arg_pass *a_pass = NULL;
    int is_https = 0;
    SSL *c_ssl = NULL;
  
    if(!host || port <= 0) {
        err = 1;
        goto end;
    }
  
    is_https = (_proto == HTTPS_COM_PROTO) ? 1 : 0;
  
    if(is_https) {
        ssl_initialization();
        _ctx = SSL_CTX_new(TLS_server_method());
        if (!_ctx) {
            VR_LOG(LOG_ERROR, "Error starting a new SSL context");
            err = 1;
            goto end;
        }

        if(SSL_CTX_use_certificate_file(_ctx, _cert_file, SSL_FILETYPE_PEM) <= 0) {
            VR_LOG(LOG_ERROR, "Error applying certificate...");
            err = 1;
            goto end;
        }
        if(SSL_CTX_use_PrivateKey_file(_ctx, _cert_file, SSL_FILETYPE_PEM) <= 0) {
            VR_LOG(LOG_ERROR, "Error applying private key file...");
            err = 1;
            goto end;
        }
    }
     
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sfd < 0) {
        VR_LOG(LOG_ERROR, "Socket creation failed");
        err = 1;
        goto end;
    }
   
    bzero(&servaddr, sizeof(servaddr));
  
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
  
    if((bind(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        VR_LOG(LOG_ERROR, "Error trying to bind");
        err = 1;
        goto end;
    }
  
    if((listen(sfd, MAX_CONCURRENT_CLIENTS)) != 0) {
        VR_LOG(LOG_ERROR, "Error trying to listen");
        err = 1;
        goto end;
    }
  
  /*
       on some systems pthread_t is an unsigned long, on other is a pointer to a structure,
        do this method in accordance with both schemes
  */
    i = 0;
    while(1) {
        if(close_srv) {
            VR_LOG(LOG_INFO, "Order to shutdown the server. Closing...");
            goto end;
        }
     
        if(i >= MAX_CONCURRENT_CLIENTS) {
            for(int x = 0 ; x < MAX_CONCURRENT_CLIENTS ; x++) {
                if(tid[x] == 0)
                    continue;
                    
                res = pthread_kill(tid[x], 0);
                if(res == 0)
                    continue;
                else if(res == ESRCH) {
                    tid[x] = 0;
                    i--;
                } else {
                    VR_LOG(LOG_ERROR, "Error checking thread status");
                    continue; /* err checking status */
                }
            }
             
        }
     
        addrlen = sizeof(servaddr);
        connfd = accept(sfd, (struct sockaddr *)&servaddr, (socklen_t *)&addrlen);
        if(connfd < 0) {
            VR_LOG(LOG_ERROR, "Error accepting conenction");
            continue;
        }
     
        if(is_https) {
            c_ssl = SSL_new(_ctx);
            SSL_set_fd(c_ssl, connfd);
     
            if(SSL_accept(c_ssl) <= 0) {
                VR_LOG(LOG_ERROR, "Error accepting SSL connection");
                continue;
            }
        }

        VR_LOG(LOG_INFO, "Client connected to relay server...");
     
        z = 0;
        while(z < MAX_CONCURRENT_CLIENTS) {
            if(tid[z] == 0)
                break;
            z++;
        }
     
        if(z == -1) {
            VR_LOG(LOG_ERROR, "Could not find a free spot. MAX_CONCURRENT_CLIENTS reached...");
            continue;
        }
     
        a_pass = (rl_arg_pass *)calloc(1, sizeof(rl_arg_pass));
        if(!a_pass) {
            err = 1;
            goto end;
        }
     
        if(_proto == TCP_COM_PROTO) {
            VR_LOG(LOG_ERROR, "_proto is TCP_COM_PROTO, though we are in an HTTP relay function. WTF");
            err = 1;
            goto end;
        }
     
        a_pass->sock = connfd;
        a_pass->c_ssl = c_ssl;
        a_pass->is_https = is_https;

        c_ssl = NULL;
     
        if(pthread_create(&tid[z], NULL, (void *)relay_http_srv_handle_req, ((void *)a_pass))) {
            VR_LOG(LOG_ERROR, "Error creating thread");
            continue;
        }

        a_pass = NULL;

        i++;
    }
  
    err = 0;
end:
    if(is_https)
        ssl_cleanup();

    z = 0;
    while(z < MAX_CONCURRENT_CLIENTS) {
        if(tid[z] == 0) {
            z++;
            continue;
        }
            
        res = pthread_cancel(tid[z]);
        if(res != 0) {
            VR_LOG(LOG_ERROR, "Error trying to cancel thread");
            continue;
        }
        z++;
    }
  
    if(err) {
        close_srv = 1;
        sleep(2);
    }
    
    close_srv = 1;

    return (err == 0);
}

int do_tcp_relay_srv(char *host, int port) {
    struct sockaddr_in servaddr;
    int sfd = 0;
    int err = 0;
    int res = 0;
    int i = 0;
    int connfd = 0;
    int z = 0;
    int addrlen = 0;
    pthread_t tid[MAX_CONCURRENT_CLIENTS] = { 0 };
  
    if(!host || port <= 0) {
        err = 1;
        goto end;
    }
     
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sfd < 0) {
        VR_LOG(LOG_ERROR, "Socket creation failed");
        err = 1;
        goto end;
    }
   
    bzero(&servaddr, sizeof(servaddr));
  
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
  
    if((bind(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        VR_LOG(LOG_ERROR, "Failed when trying to bind");
        err = 1;
        goto end;
    }
  
    if((listen(sfd, MAX_CONCURRENT_CLIENTS)) != 0) {
        VR_LOG(LOG_ERROR, "Failed when trying to listen");
        err = 1;
        goto end;
    }
  
  /*
   on some systems pthread_t is an unsigned long, on other is a pointer to a structure,
   do this method in accordance with both schemes
  */
    i = 0;
    while(1) {
        if(close_srv) {
            VR_LOG(LOG_INFO, "Order to shutdown the server. Closing...");
            goto end;
        }
     
        if(i >= MAX_CONCURRENT_CLIENTS) {
            for(int x = 0 ; x < MAX_CONCURRENT_CLIENTS ; x++) {
                if(tid[x] == 0)
                    continue;
                    
                res = pthread_kill(tid[x], 0);
                if(res == 0)
                    continue;
                else if(res == ESRCH) {
                    tid[x] = 0;
                    i--;
                } else {
                    VR_LOG(LOG_ERROR, "Error checking thread status...");
                    continue; /* err checking status */
                }
            }
        }
     
        addrlen = sizeof(servaddr);
        connfd = accept(sfd, (struct sockaddr *)&servaddr, (socklen_t *)&addrlen);
        if(connfd < 0) {
            VR_LOG(LOG_ERROR, "Failed when accepting new connection");
            continue;
        }

        VR_LOG(LOG_INFO, "Client connected to relay server...");

        z = 0;
        while(z < MAX_CONCURRENT_CLIENTS) {
            if(tid[z] == 0)
                break;
            z++;
        }
     
        if(z == -1) {
            VR_LOG(LOG_ERROR, "Could not find a free spot. MAX_CONCURRENT_CLIENTS reached...");
            continue;
        }

        if(pthread_create(&tid[z], NULL, (void *)relay_tcp_srv_poll, ((void *)(uint64_t)connfd))) {
            VR_LOG(LOG_ERROR, "Error creating thread");
            continue;
        }
     
        i++;
  
    }
  
    err = 0;
end:
    z = 0;
    while(z < MAX_CONCURRENT_CLIENTS) {
        if(tid[z] == 0) {
            z++;
            continue;
        }
            
        res = pthread_cancel(tid[z]);
        if(res != 0) {
            VR_LOG(LOG_ERROR, "Error trying to cancel thread...");
            continue;
        }
        z++;
    }
  
    if(err) {
        close_srv = 1;
        sleep(2);
    }
    
    close_srv = 1;
  
    return (err == 0);
}

void start_relay_srv(arg_pass *arg) {
    char *relay_host = NULL;
    int relay_port = 0;
    proto_t proto = 0;
    int r = 0;
    int err = 0;
  
    if(!arg) {
        err = 1;
        goto end;
    }
     
    relay_host = arg->host;
    relay_port = arg->port;
    proto = arg->proto;

    if(!relay_host || relay_port <= 0) {
        VR_LOG(LOG_ERROR, "Invalid host or port provided for relay server");
        err = 1;
        goto end;
    }
  
    if(proto == TCP_COM_PROTO) {
        r = do_tcp_relay_srv(relay_host, relay_port);
    } else if(proto == HTTP_COM_PROTO ||
                proto == HTTPS_COM_PROTO) {
            r = do_http_relay_srv(relay_host, relay_port);
    } else {
        VR_LOG(LOG_ERROR, "Unknown protocol received...");
        err = 1;
        goto end;
    }
  
    if(r <= 0) {
        VR_LOG(LOG_ERROR, "Unknown error in relay server");
        err = 1;
        goto end;
    }
  
    err = 0;
end:
    if(arg) {
        free(arg);
        arg = NULL;
    }
  
    if(err) {
        close_srv = 1;
        sleep(2);
    }
    
    close_srv = 1;
  
    pthread_exit(NULL);
    return;
}

int __start_proxy_srv(char *proxy_host, int proxy_port) {
    pthread_t th;
    arg_pass *arg = NULL;
  
    if(!proxy_host || proxy_port <= 0)
        return 0;
  
    arg = calloc(1, sizeof(arg_pass));
    if(!arg)
        return 0;
     
    arg->host = proxy_host;
    arg->port = proxy_port;
    arg->proto = TCP_COM_PROTO;
     
    if(pthread_create(&th, NULL, (void *)start_proxy_srv, (void *)arg)) {
        VR_LOG(LOG_ERROR, "Error creating thread");
        return 0;
    }
     
    return 1;
}

int __start_relay_srv(char *relay_host, int relay_port, proto_t proto) {
    pthread_t th;
    arg_pass *arg = NULL;
  
    if(!relay_host || relay_port <= 0)
        return 0;
  
    arg = calloc(1, sizeof(arg_pass));
    if(!arg)
        return 0;
     
    arg->host = relay_host;
    arg->port = relay_port;
    arg->proto = proto;
     
    if(pthread_create(&th, NULL, (void *)start_relay_srv, (void *)arg)) {
        VR_LOG(LOG_ERROR, "Error creating thread");
        return 0;
    }
     
    return 1;
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

/*

proto:
- 0: HTTPS_COM_PROTO (HTTPS)
- 1: HTTP_COM_PROTO (HTTP)
- 2: TCP_COM_PROTO (TCP)

*/
int start_socks4_rev_proxy(char *proxy_host, int proxy_port, char *relay_host, int relay_port, proto_t proto, char *key, size_t key_sz, char *cert_file, int *err) {
    int fail = 0;

    VR_LOG(LOG_INFO, "Starting VROUTE server version '%s'...", VROUTE_VERSION);

    if(!proxy_host || proxy_port <= 0) {
        VR_LOG(LOG_ERROR, "Invalid host provided");
        fail = INVALID_PARAMETER;
        goto end;
    }

    if(!relay_host || relay_port <= 0) {
        VR_LOG(LOG_ERROR, "Invalid port provided");
        fail = INVALID_PARAMETER;
        goto end;
    }

    if(proto != HTTPS_COM_PROTO && proto != HTTP_COM_PROTO &&
                    proto != TCP_COM_PROTO) {
        VR_LOG(LOG_ERROR, "Unknown protocol requested for server");
        fail = INVALID_PARAMETER;
        goto end;
    }
  
    if(proto == HTTPS_COM_PROTO && (!cert_file || strlen(cert_file) == 0)) {
        VR_LOG(LOG_ERROR, "HTTPS protocol requested, yet cert path not provided");
        fail = INVALID_PARAMETER;
        goto end;
    }
  
    if(proto == HTTPS_COM_PROTO && !file_exists(cert_file)) {
        VR_LOG(LOG_ERROR, "HTTPS protocol requested, yet cert path does not exist");
        fail = INVALID_PARAMETER;
        goto end;
    }
  
    if(!key || key_sz == 0) {
        VR_LOG(LOG_ERROR, "Key not provided and mandatory");
        fail = INVALID_PARAMETER;
        goto end;
    }
  
    if(key_sz > MAX_KEY_SIZE) {
        VR_LOG(LOG_ERROR, "Key size exceeds maximum value");
        fail = INVALID_PARAMETER;
        goto end;
    }

    if(!is_valid_host_or_ip_addr(proxy_host)) {
        VR_LOG(LOG_ERROR, "Provided proxy host is not valid");
        fail = INVALID_PARAMETER;
        goto end;
    }

    if(!is_valid_proxy_or_relay_port(proxy_port)) {
        VR_LOG(LOG_ERROR, "Provided proxy port is not valid");
        fail = INVALID_PARAMETER;
        goto end;
    }

    if(!is_valid_host_or_ip_addr(relay_host)) {
        VR_LOG(LOG_ERROR, "Provided relay host is not valid");
        fail = INVALID_PARAMETER;
        goto end;
    }

    if(!is_valid_proxy_or_relay_port(relay_port)) {
        VR_LOG(LOG_ERROR, "Provided relay port is not valid");
        fail = INVALID_PARAMETER;
        goto end;
    }
    
    VR_LOG(LOG_DEBUG, "Allocating and initializing proxy_client_conns...");

    if(!proxy_client_conns) {
        proxy_client_conns = (proxy_client_def *)calloc(MAX_CONCURRENT_PROXY_CLIENTS, sizeof(proxy_client_def));
        if(!proxy_client_conns) {
            fail = OUT_OF_MEMORY_ERROR;
            goto end;
        }
    }
    
    VR_LOG(LOG_DEBUG, "Allocating and initializing client_conns...");

    if(!client_conns) {
        client_conns = (conn_def *)calloc(MAX_CONCURRENT_CLIENTS, sizeof(conn_def));
        if(!client_conns) {
            fail = OUT_OF_MEMORY_ERROR;
            goto end;
        }
    }
    
    VR_LOG(LOG_DEBUG, "Allocating and initializing handshake_defs...");
  
    if(!handshake_defs) {
        handshake_defs = (http_handshake_def *)calloc(MAX_CONCURRENT_CLIENTS, sizeof(http_handshake_def));
        if(!handshake_defs) {
            fail = OUT_OF_MEMORY_ERROR;
            goto end;
        }
    }
    
    VR_LOG(LOG_DEBUG, "Allocating and initializing conn_req_glb...");
    
    if(!conn_req_glb) {
        conn_req_glb = (conn_open_req *)calloc(MAX_CONCURRENT_CONN_OPEN, sizeof(conn_open_req));
        if(!conn_req_glb) {
            fail = OUT_OF_MEMORY_ERROR;
            goto end;
        }
    }
  
    if(proto == HTTP_COM_PROTO)
        VR_LOG(LOG_INFO, "Using protocol: HTTP_COM_PROTO");
    else if(proto == HTTPS_COM_PROTO)
        VR_LOG(LOG_INFO, "Using protocol: HTTPS_COM_PROTO");
    else if(proto == TCP_COM_PROTO)
        VR_LOG(LOG_INFO, "Using protocol: TCP_COM_PROTO");
    
    VR_LOG(LOG_DEBUG, "Allocating and initializing global definitions...");
    
    _key = memdup(key, key_sz);
    _key_sz = key_sz;
    _proto = proto;
    
    if(cert_file)
       _cert_file = strdup(cert_file);
    
    VR_LOG(LOG_INFO, "Starting SOCKS proxy server at: %s:%d...", IN_ANY_ADDR, proxy_port);
  
    if(!__start_proxy_srv(proxy_host, proxy_port)) {
        VR_LOG(LOG_ERROR, "Unknown error occurred while starting SOCKS proxy server");
        fail = SERVER_UNKNOWN_ERR;
        goto end;
    }
    
    VR_LOG(LOG_INFO, "Starting relay server at: %s:%d...", IN_ANY_ADDR, relay_port);
  
    if(!__start_relay_srv(relay_host, relay_port, proto)) {
        VR_LOG(LOG_ERROR, "Unknown error occurred while starting relay server");
        fail = SERVER_UNKNOWN_ERR;
        goto end;
    }
    
    VR_LOG(LOG_INFO, "Starting ping worker...");
  
    __ping_worker();
  
    while(1) {
        if(close_srv) {
            VR_LOG(LOG_INFO, "Order to close server. Closing...");
            break;
        }
        sleep(2);
    }

    fail = 0;
end:
    if(fail)
        VR_LOG(LOG_INFO, "Closing VROUTE server. Status: FAILURE");
    else
        VR_LOG(LOG_INFO, "Closing VROUTE server. Status: NORMAL");
    
    if(fail == 0) {
        if(err)
            *err = 0;
    }

    if(fail) {
        if(err)
            *err = fail;
    }
    
    VR_LOG(LOG_DEBUG, "Closing all proxy clients...");
    close_all_proxy_clients();
    
    VR_LOG(LOG_DEBUG, "Closing all relay clients...");
    close_all_clients();
    
    if(conn_req_glb) {
        free(conn_req_glb);
        conn_req_glb = NULL;
    }
  
    if(proxy_client_conns) {
        free(proxy_client_conns);
        proxy_client_conns = NULL;
    }
  
    if(client_conns) {
        free(client_conns);
        client_conns = NULL;
    }
    
    if(handshake_defs) {
        free(handshake_defs);
        handshake_defs = NULL;
    }
  
    if(_key) {
        free(_key);
        _key = NULL;
    }
  
    return (fail == 0);
}

void socks4_rev_close_srv(void) {
    close_srv = 1;
    sleep(4);
    return;
}

char *socks4_rev_strerror(int err) {
    char *str_err = NULL;

    switch(err) {
        case SERVER_UNKNOWN_ERR:
            str_err = "(SERVER_UNKNOWN_ERR): unknown error occurred";
            break;
        case OUT_OF_MEMORY_ERROR:
            str_err = "(OUT_OF_MEMORY_ERROR): allocation failed because there is no more available memory";
            break;
        case INVALID_PARAMETER:
            str_err = "(INVALID_PARAMETER): invalid parameter provided to the library";
            break;
        default:
            str_err = "(?): unknown error";
            break;
    }
    return str_err;
}

#if !COMPILE_AS_LIBRARY

void usage(void) {
    printf("==== { VROUTE SERVER: USAGE } ===\n");
    printf("\n[0] => HTTPS protocol\n[1] => HTTP protocol\n[2] => Raw TCP protocol\n\n");
    printf("./vroutesrv <proxy ip> <proxy port> <relay ip> <relay port> <protocol> <password> <cert path (if https)>\n\n");
    printf("  Eg.: ./vroutesrv 0.0.0.0 1080 0.0.0.0 1337 1 p@ssw0rd1234#\n\n");
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
    proto_t protocol = 0;
    int err = 0;
    
    if(argc < 7) {
        usage();
        return 0;
    }
    
    proto_n = atoi(argv[5]);
    
    if(proto_n == 0) {
        protocol = HTTPS_COM_PROTO;
    } else if(proto_n == 1) {
        protocol = HTTP_COM_PROTO;
    } else if(proto_n == 2) {
        protocol = TCP_COM_PROTO;
    } else {
        usage();
        return 0;
    }
    
    if(protocol == HTTPS_COM_PROTO && argc != 8) {
        usage();
        return 0;
    }
    
    proxy_host = strdup(argv[1]);
    proxy_port = atoi(argv[2]);
    relay_host = strdup(argv[3]);
    relay_port = atoi(argv[4]);

    password = strdup(argv[6]);
    
    if(protocol == HTTPS_COM_PROTO)
        cert_path = strdup(argv[7]);
        
    if(!password) {
        usage();
        return 0;
    }
    
    if(!start_socks4_rev_proxy(proxy_host, proxy_port, relay_host, relay_port, protocol, password, strlen(password), cert_path, &err)) {
        VR_LOG(LOG_ERROR, "Error.: Server failed. (%d): %s\n", err, socks4_rev_strerror(err));
        
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

#endif




