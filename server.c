/*

...

- make ping worker close HTTP(S) connections whole last connection is more than a specific time defined
- make small proto specification for HTTP(S) headers to register new session, send or receive data and specify client id (in TCP
    a single TCP connection means a single client though)

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

#define MAX_CONCURRENT_PROXY_CLIENTS 1024
#define MAX_CONCURRENT_CLIENTS 1024
#define MAX_CONCURRENT_CHANNELS_PER_CLIENT 2048
#define MAX_CONCURRENT_QUEUED_BUFFERS MAX_CONCURRENT_CLIENTS * 256

#define MAX_HOSTNAME_SIZE 255

#define MAX_KEY_SIZE 64

typedef enum {
  HTTPS_COM_PROTO = 0,
  HTTP_COM_PROTO = 1,
  TCP_COM_PROTO = 2
} proto_t;

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

typedef struct _buffer_queue {
  int client_id;
  size_t size;
  time_t queue_time;
  buffer_queue *next;
  char data[0];
} buffer_queue;

typedef struct _proxy_client_def {
  int proxy_client_id;
  int sock;
  int channel_id;
  int32_t client_ip_addr;
  int16_t orig_port;
} proxy_client_def;

typedef struct _com_buffer_def {
  int channel_id; // will be 0 if still not assigned or if a command (eg.: when iterating to find routes)
  int client_id;
  char *data;
  size_t size;
} com_buffer_def;

typedef struct __attribute__((packed)) _socks_hdr {
  uint8_t vn;
  uint8_t cd;
  uint16_t dstport;
  uint32_t dstip;
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
  FORWARD_CONNECTION_FAILURE
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
} arg_pass;

typedef struct _cmd_def {
  int cmd;
  unsigned char value;
  char *name;
} cmd_def;

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

int close_srv = 0;
conn_def *client_conns = NULL;
proxy_client_def *proxy_client_conns = NULL;

buffer_queue *queue_head = NULL;

char *_key = NULL;
size_t _key_sz = 0;

void ping_worker(void) {
  long curr_time = 0;
  while(1) {
    sleep(10);
    curr_time = time(NULL);
    if(close_srv) {
      pthread_exit(1);
      return;
    }
    // ...go through every client in both proxy and relay servers...
  }
  pthread_exit(0);
}

void __ping_worker(void) {
  pthread_t th;
  pthread_create(&th, NULL, ping_worker, NULL);
  return;
}

void shutdown_srv(void) {
  close_srv = 1;
  return;
}

uint16_t generate_channel_id(void) {
  return (uint16_t)rand();
}

int cl_channel_id_exists(int channel_id, int client_idx) {
  // XXX: locking relies on caller
  int idx = -1;

  if(channel_id < 0)
    return 0;

  if(!client_conns || client_idx < 0 || client_idx > MAX_CONCURRENT_CLIENTS || !client_conns[client_idx].c_channels)
    return 0;

  for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS_PER_CLIENT ; x++) {
    if(client_conns[client_idx].c_channels[x].channel_id == channel_id) {
      idx = x;
      break;
    }
  }

  if(idx == -1)
    return 0;
  return 1;
}

int channel_id_exists(int channel_id) {
  // TODO: add locking
  int idx = -1;

  if(channel_id <= 0)
    return 0;

  for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
    if(client_conns[i].c_channels) {
      if(cl_channel_id_exists(channel_id, i)) {
        idx = i;
        break;
      }
    }
  }

  if(idx == -1)
    return 0;
  return 1;
}

int create_channel() {
  //...
  while(1) {
    channel_id = generate_channel_id();
    if(channel_id != 0 && !channel_id_exists(channel_id))
      break;
  }
  // ...
  // TODO
}

int parse_socks_hdr(char *data, size_t data_sz, char **host, int **port) {
  if(!data || data_sz == 0 || !host || !port)
    return 0;
  // ...
  // TODO
  return 1;
}

void collect_dead_clients_worker(void) {
  // ... for TCP conns try to connect, if fails remove client...
  // ...for HTTP(S) conns set a max last_conn_timestamp...
  // TODO
  return;
}

int send_remote_cmd(int sock, scmt_t cmd, int channel_id) {
  // TODO
  return 1;
}

int interpret_remote_cmd(char *cmd, size_t cmd_sz) {
  // TODO
  return 1;
}

int proxy_srv_poll(void) {
  // TODO
  return 1;
}

int relay_srv_poll(void) {
  // TODO
  return 1;
}

int start_proxy_srv(arg_pass *arg) {
  char *proxy_host = NULL;
  int proxy_port = 0;
  
  if(!arg)
     return 0;
     
  proxy_host = arg->host;
  proxy_port = arg->port;

  if(!proxy_host || proxy_port <= 0)
     return 0;
     
  // TODO
  
  if(arg) {
     free(arg);
     arg = NULL;
  }
  
  return 1;
}

int start_relay_srv(arg_pass *arg) {
  char *relay_host = NULL;
  int relay_port = 0;
  
  if(!arg)
     return 0;
     
  relay_host = arg->host;
  relay_port = arg->port;
  
  if(!relay_host || relay_port <= 0)
     return 0;
     
  // TODO
  
  if(arg) {
     free(arg);
     arg = NULL;
  }
  
  return 1;
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
     
  if(pthread_create(&th, NULL, start_proxy_srv, (void *)arg))
     return 0;
     
  return 1;
}

int __start_relay_srv(char *relay_host, int relay_port) {
  pthread_t th;
  arg_pass *arg = NULL;
  
  if(!relay_host || relay_port <= 0)
     return 0;
  
  arg = calloc(1, sizeof(arg_pass));
  if(!arg)
     return 0;
     
  arg->host = relay_host;
  arg->port = relay_port;
     
  if(pthread_create(&th, NULL, start_relay_srv, (void *)arg))
     return 0;
     
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
int start_socks4_rev_proxy(char *proxy_host, int proxy_port, char *relay_host, int relay_port, proto_t proto, char *key, size_t key_sz, int *err) {
  int fail = 0;

  if(!proxy_host || proxy_port <= 0) {
    fail = INVALID_PARAMETER;
    goto end;
  }

  if(!relay_host || relay_port <= 0) {
    fail = INVALID_PARAMETER;
    goto end;
  }

  if(proto != HTTPS_COM_PROTO && proto != HTTP_COM_PROTO &&
          proto != TCP_COM_PROTO) {
    fail = INVALID_PARAMETER;
    goto end;
  }
  
  if(!key || key_sz == 0) {
    fail = INVALID_PARAMETER;
    goto end;
  }
  
  if(key_sz > MAX_KEY_SIZE) {
    fail = INVALID_PARAMETER;
    goto end;
  }

  if(!is_valid_host_or_ip_addr(proxy_host)) {
    fail = INVALID_PARAMETER;
    goto end;
  }

  if(!is_valid_proxy_or_relay_port(proxy_port)) {
    fail = INVALID_PARAMETER;
    goto end;
  }

  if(!is_valid_host_or_ip_addr(relay_host)) {
    fail = INVALID_PARAMETER;
    goto end;
  }

  if(!is_valid_proxy_or_relay_port(relay_port)) {
    fail = INVALID_PARAMETER;
    goto end;
  }

  if(!proxy_client_conns) {
    proxy_client_conns = (proxy_client_def *)calloc(MAX_CONCURRENT_PROXY_CLIENTS, sizeof(proxy_client_def));
    if(!proxy_client_conns)
      fail = OUT_OF_MEMORY_ERROR;
      goto end;
  }

  if(!client_conns) {
    client_conns = (conn_def *)calloc(MAX_CONCURRENT_CLIENTS, sizeof(conn_def));
    if(!client_conns)
      fail = OUT_OF_MEMORY_ERROR;
      goto end;
  }
  
  _key = memdup(key, key_sz);
  _key_sz = key_sz;
  
  if(!__start_proxy_srv(proxy_host, proxy_port)) {
     fail = SERVER_UNKNOWN_ERR;
     goto end;
  }
  
  if(!__start_relay_srv(relay_host, relay_port)) {
     fail = SERVER_UNKNOWN_ERR;
     goto end;
  }
  
  __ping_worker();

  // start in a new thread start_proxy_srv and start_relay_srv
  // start a poll that does multiple stuff like collect_dead_clients_worker in main thread
  // check for close_srv in every thread, if 1, close all of them
  
  // TODO
  
  while(1) {
     if(close_srv)
        break;
     sleep(2);
  }

  fail = 0;
end:
  if(fail == 0) {
    if(err)
      *err = 0;
  }

  if(fail) {
    if(err)
      *err = fail;
  }
  
  // TODO: cleanup contained pointers too!
  
  if(proxy_client_conns) {
     free(proxy_client_conns);
     proxy_client_conns = NULL;
  }
  
  if(client_conns) {
     free(client_conns);
     client_conns = NULL;
  }
  
  if(_key) {
     free(_key);
     _key = NULL;
  }
  
  return (fail == 0);
}

char *socks4_rev_strerror(int err) {
  // TODO
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

int start_socks4_rev_proxy_nb(char *proxy_host, int proxy_port, char *relay_host, int relay_port, proto_t proto, char *key, size_t key_sz, int *err) {
  // non-blocking version of start_socks4_rev_proxy()
  // TODO
  return 1;
}

#define PSK "p@ssw0rd_3241!!=#"

int main(void) {
  int err = 0;
  // note: NULL is allowed for &err arg
  // generate error codes and a translate-to-error-string table on socks4_rev_strerror() to get error information
  if(!start_socks4_rev_proxy("127.0.0.1", 1080, "127.0.0.1", 1337, TCP_COM_PROTO, PSK, strlen(PSK), &err)) {
      printf("Error.: Server failed. (%d): %s\n", err, socks4_rev_strerror(err));
      return 1;
  }
  return 0;
}





