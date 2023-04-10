/*

TODO:
- add locking
- HTTP thingy
- close sock or c_ssl
- functions to cleanup proxy_client_conns and client_conns (contained pointers) in case srv_close is set
- properly handle srv_close in every aspect of the program execution flow
- HTTPS impl

- relationship points between both servers (client_ids, channel_ids, queued buffers etc)

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

#include "tp/base64.h"

#define DEBUG 1

#define CHALLENGE_DEFAULT_SIZE 64

#define MAX_CONCURRENT_PROXY_CLIENTS 1024
#define MAX_CONCURRENT_CLIENTS 1024
#define MAX_CONCURRENT_CHANNELS_PER_CLIENT 2048
#define MAX_CONCURRENT_QUEUED_BUFFERS MAX_CONCURRENT_CLIENTS * 256

#define MAX_HOSTNAME_SIZE 255

#define MAX_KEY_SIZE 64

#define RELAY_BUFFER_SIZE 4096

#define DATA_PREFIX "<img src='data:image/jpeg;base64,"
#define DATA_SUFFIX "' />"

#define DATA_INPUT_PREFIX "token="
#define DATA_INPUT_SUFFIX "; expire=0;"

#define MIN_CLIENT_ID 0x0000111111111111
#define MAX_CLIENT_ID 0x0000ffffffffffff

#define MIN_CHANNEL_ID 0x0000111111111111
#define MAX_CHANNEL_ID 0x0000ffffffffffff

#define MIN_CHALL_CHR_VAL 0x01
#define MAX_CHALL_CHR_VAL 0xff

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

typedef struct _http_handshake_def {
  int h_id;
  char *challenge;
  char *solution;
  int is_solved;
} http_handshake_def;

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

http_handshake_def *handshake_defs = NULL;

char *_key = NULL;
size_t _key_sz = 0;
proto_t _proto = 0;

void ping_worker(void) {
  long curr_time = 0;
  while(1) {
    sleep(10);
    curr_time = time(NULL);
    if(close_srv) {
      pthread_exit(1);
      return;
    }
    // TODO: ...go through every client in both proxy and relay servers...
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

uint64_t generate_client_id(void) {
    uint64_t client_id = (rand() % (MAX_CLIENT_ID - MIN_CLIENT_ID + 1)) + MIN_CLIENT_ID;
    return client_id;
} 

uint64_t generate_channel_id(void) {
    uint64_t channel_id = (rand() % (MAX_CHANNEL_ID - MIN_CHANNEL_ID + 1)) + MIN_CHANNEL_ID;
    return channel_id;
}

char *generate_random_challenge(void) {
   char *chall = NULL;
   unsigned char c = 0;
   
   chall = calloc(CHALLENGE_DEFAULT_SIZE + 1, sizeof(char));
   if(!chall)
       return NULL;
       
   for(int i = 0 ; i < CHALLENGE_DEFAULT_SIZE ; i++) {
       c = (rand() % (0xff - 0x01 + 1)) + 0x01;
       chall[i] = c;
   }
   
   return chall;
}

int handshake_sess_exists(int h_id) {
   int idx = -1;
   // XXX: add locking
   
   if(h_id < 0)
     return 0;
     
   for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
      if(handshake_defs[i].h_id == h_id) {
        idx = i;
        break;
      }
   }
   
   if(idx == -1) {
      return 0;
   }
     
   return 1;
}

int is_challenge_solved(int h_id) {
   int idx = -1;
   int r = 0;
   // XXX: add locking
   
   if(h_id < 0)
     return 0;
     
   for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
      if(handshake_defs[i].h_id == h_id) {
        idx = i;
        break;
      }
   }
   
   if(idx == -1) {
      return 0;
   }
   
   r = handshake_defs[idx].is_solved;
   if(r == 0)
     return 0;
     
   return 1;
}

int mark_challenge_solved(int h_id) {
   int idx = -1;
   // XXX: add locking
   
   if(h_id < 0)
     return 0;
     
   for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
      if(handshake_defs[i].h_id == h_id) {
        idx = i;
        break;
      }
   }
   
   if(idx == -1) {
      return 0;
   }
   
   handshake_defs[idx].is_solved = 1;
     
   return 1;
}

int create_handshake(int h_id) {
   int idx = -1;
   char *chall = NULL;
   char *sol_a = NULL;
   char *sol = NULL;
   size_t sol_size_a = 0;
   size_t sol_size = 0;
   // XXX: add locking

   if(h_id < 0)
     return 0;
     
   for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
      if(handshake_defs[i].h_id == 0) {
        idx = i;
        break;
      }
   }
   
   if(idx == -1) {
      return 0;
   }
   
   chall = generate_random_challenge();
   if(!chall) {
      return 0;
   }
   
   sol_a = encrypt_challenge(chall, CHALLENGE_DEFAULT_SIZE, _key, _key_sz, &sol_size_a);
   if(!sol_a) {
      if(chall) {
        free(chall);
        chall = NULL;
      }
      return 0;
   }
   
    sol = sha256_hash(sol_a, sol_size_a, &sol_size);
    if(!sol) {
        if(chall) {
          free(chall);
          chall = NULL;
        }

        if(sol_a) {
          free(sol_a);
          sol_a = NULL;
        }
        return NULL;
    }

   if(sol_a) {
     free(sol_a);
     sol_a = NULL;
   }
   
   handshake_defs[idx].h_id = h_id;
   handshake_defs[idx].challenge = chall;
   handshake_defs[idx].solution = sol;
   handshake_defs[idx].sol_size = sol_size;
   handshake_defs[idx].is_solved = 0;
   
   return 1;
}

int delete_handshake(int h_id) {
   int idx = -1;
   // XXX: add locking
   
   if(h_id < 0)
     return 0;
   
   for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
      if(handshake_defs[i].h_id == h_id) {
        idx = i;
        break;
      }
   }
   
   if(idx == -1) {
      return 0;
   }
   
   handshake_defs[idx].h_id = 0;
   handshake_defs[idx].is_solved = 0;
   
   if(handshake_defs[idx].challenge) {
      free(handshake_defs[idx].challenge);
      handshake_defs[idx].challenge = NULL;
   }
   
   if(handshake_defs[idx].solution) {
      free(handshake_defs[idx].solution);
      handshake_defs[idx].solution = NULL;
   }
   
   handshake_defs[idx].sol_size = 0;
   
   return 1;
}

char *get_challenge(int h_id) {
   int idx = -1;
   char *chall = NULL;
   // XXX: add locking
   
   if(h_id < 0)
     return NULL;
   
   for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
      if(handshake_defs[i].h_id == h_id) {
        idx = i;
        break;
      }
   }
   
   if(idx == -1) {
      return NULL;
   }
   
   chall = handshake_defs[idx].challenge;
   
   return chall;
}

char *get_h_challenge_solution(int h_id, size_t *out_size) {
   int idx = -1;
   char *sol = NULL;
   size_t sol_size = 0;
   // XXX: add locking
   
   if(h_id < 0 || !out_size)
     return NULL;
     
   *out_size = 0;
   
   for(int i = 0 ; i < MAX_CONCURRENT_CLIENTS ; i++) {
      if(handshake_defs[i].h_id == h_id) {
        idx = i;
        break;
      }
   }
   
   if(idx == -1) {
      return NULL;
   }
   
   sol = handshake_defs[idx].solution;
   sol_size = handshake_defs[idx].sol_size;
   
   *out_size = sol_size;
   return sol;
}

void *memdup(const void *mem, size_t size) { 
   void *out = calloc(size, sizeof(char));
   if(out != NULL)
       memcpy(out, mem, size);
   return out;
}

char *generate_random_iv(size_t *out_sz) {
   char *iv = NULL;
   unsigned char c = 0;
   
   if(!out_sz)
       return NULL;
   
   *out_sz = 0;
   
   iv = calloc(AES_IV_SIZE + 1, sizeof(char));
   if(!iv)
       return NULL;
       
   for(int i = 0 ; i < AES_IV_SIZE ; i++) {
       c = (rand() % (MAX_IV_CHAR_RANGE - MIN_IV_CHAR_RANGE + 1)) + MIN_IV_CHAR_RANGE;
       iv[i] = c;
   }
   
   *out_sz = AES_IV_SIZE;
   
   return iv;
}

size_t get_decrypted_size(char *enc, size_t enc_sz) {
    size_t padding_size = enc[enc_sz - 1];
    return enc_sz - padding_size;;
}

char *sha256_hash(char *data, size_t size, size_t *out_sz) {
    char *hash = NULL;
    unsigned char hash_fixed[SHA256_DIGEST_LENGTH + 1] = { 0 };
    
    if(!data || size == 0 || !out_sz)
        return NULL;
    
    *out_sz = 0;
    
    SHA256(data, size, hash_fixed);
    
    hash = memdup(hash_fixed, SHA256_DIGEST_LENGTH);
    *out_sz = SHA256_DIGEST_LENGTH;
    
    return hash;
}

char *PKCS7_pad(char *data, size_t data_sz, int bs, size_t *out_size, int is_chall) {
    EVP_CIPHER_CTX *ctx = NULL;
    int padded_len = 0;
    char *ptr = NULL;
    
    if(!data || data_sz == 0 || bs < 0 || !out_size || is_chall < 0)
        return NULL;

    *out_size = 0;

    ptr = calloc(data_sz + bs, sizeof(char));
    if(!ptr)
        return NULL;
    
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    if(is_chall)
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, NULL, NULL);
    else
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);

    EVP_EncryptUpdate(ctx, ptr, &padded_len, data, data_sz);
    EVP_EncryptFinal_ex(ctx, ptr + padded_len, &padded_len);

    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    
    *out_size = data_sz + bs - padded_len;

    return ptr;
}

char *PKCS7_unpad(char *data, size_t data_sz, int bs, size_t *out_size, int is_chall) {
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0;
    char *ptr = NULL;
    
    if(!data || data_sz == 0 || bs < 0 || !out_size || is_chall < 0)
        return NULL;
        
    *out_size = 0;
    
    ptr = calloc(data_sz, sizeof(char));
    if(!ptr)
        return NULL;

    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    if(is_chall)
        EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, NULL, NULL);
    else
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);

    EVP_DecryptUpdate(ctx, ptr, &out_len, data, data_sz - bs);
    EVP_DecryptFinal_ex(ctx, ptr + out_len, &out_len);

    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    
    *out_size = out_len;

    return ptr;
}

char *encrypt_data(char *data, size_t data_sz, char *key, size_t key_sz, size_t *out_size) {
  char *h_key = NULL;
  size_t h_sz = 0;
  AES_KEY aes_key;
  size_t out_iv_sz = 0;
  char *ciphertext = NULL;
  size_t ciphertext_sz = 0;
  char *padded = NULL;
  size_t padded_size = 0;
  char *iv = NULL;
  
  if(!data || data_sz == 0 || !key || key_sz == 0 || !out_size)
    return NULL;
    
  *out_size = 0;
  
  h_key = sha256_hash(key, key_sz, &h_sz);
  if(!h_key || h_sz == 0)
      return NULL;
      
  AES_set_encrypt_key(h_key, 256, &aes_key);
  
  iv = generate_random_iv(&out_iv_sz);
  if(!iv || out_iv_sz != AES_IV_SIZE) {
      if(h_key) {
          free(h_key);
          h_key = NULL;
      }
      return NULL;
  }
  
  padded = PKCS7_pad(data, data_sz, AES_BLOCK_SIZE, &padded_size, 0);
  if(!padded) {
      if(h_key) {
          free(h_key);
          h_key = NULL;
      }

      if(iv) {
          free(iv);
          iv = NULL;
      }
      
      return NULL;
  }
  
  ciphertext_sz = (padded_size / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
  ciphertext = calloc(AES_IV_SIZE + ciphertext_sz, sizeof(char));
  if(!ciphertext) {
	  if(iv) {
	      free(iv);
	      iv = NULL;
	  }
	  
	  if(h_key) {
	      free(h_key);
	      h_key = NULL;
	  }
	  
	  if(padded) {
	      free(padded);
	      padded = NULL;
	  }
	  
	  return NULL;
  }
  
  AES_cbc_encrypt(padded, ciphertext + AES_IV_SIZE, padded_size, &aes_key, iv, AES_ENCRYPT);
  
  if(iv) {
      free(iv);
      iv = NULL;
  }
  
  if(h_key) {
      free(h_key);
      h_key = NULL;
  }
  
  if(padded) {
      free(padded);
      padded = NULL;
  }
  
  memcpy(ciphertext, iv, AES_IV_SIZE);
  
  *out_size = AES_IV_SIZE + ciphertext_sz;

  return ciphertext;
}

char *decrypt_data(char *data, size_t data_sz, char *key, size_t key_sz, size_t *out_size) {
  char *h_key = NULL;
  size_t h_sz = 0;
  AES_KEY aes_key;
  char *iv = NULL;
  char *cleartext = NULL;
  size_t cleartext_sz = 0;
  char *unpadded = NULL;
  size_t unpadded_size = 0;
  
  if(!data || data_sz == 0 || data_sz <= AES_IV_SIZE || !key || key_sz == 0 || !out_size)
    return NULL;
    
  *out_size = 0;
  
  cleartext_sz = get_decrypted_size(data + AES_IV_SIZE, data_sz - AES_IV_SIZE);
  if(cleartext_sz == 0)
      return NULL;

  h_key = sha256_hash(key, key_sz, &h_sz);
  if(!h_key || h_sz == 0)
      return NULL;
      
  AES_set_encrypt_key(h_key, 256, &aes_key);
  
  iv = memdup(data, AES_IV_SIZE);
  if(!iv) {
	  if(h_key) {
	      free(h_key);
	      h_key = NULL;
	  }
	  return NULL;
  }
  
  cleartext = calloc(cleartext_sz, sizeof(char));
  if(!cleartext) {
	  if(iv) {
	      free(iv);
	      iv = NULL;
	  }
	  
	  if(h_key) {
	      free(h_key);
	      h_key = NULL;
	  }
	  return NULL;
  }
  
  AES_cbc_encrypt(data + AES_IV_SIZE, cleartext, data_sz - AES_IV_SIZE, &aes_key, iv, AES_DECRYPT);
  
  if(iv) {
      free(iv);
      iv = NULL;
  }
  
  if(h_key) {
      free(h_key);
      h_key = NULL;
  }
  
  unpadded = PKCS7_unpad(cleartext, cleartext_sz, AES_BLOCK_SIZE, &unpadded_size, 0);
  if(!unpadded) {
      if(cleartext) {
          free(cleartext);
          cleartext = NULL;
      }
  }
  
  if(cleartext) {
      free(cleartext);
      cleartext = NULL;
  }
  
  *out_size = unpadded_size;
  
  return unpadded;
}

char *encrypt_challenge(char *data, size_t data_sz, char *key, size_t key_sz, size_t *out_size) {
  char *h_key = NULL;
  size_t h_sz = 0;
  AES_KEY aes_key;
  size_t out_iv_sz = 0;
  char *ciphertext = NULL;
  size_t ciphertext_sz = 0;
  char *padded = NULL;
  size_t padded_size = 0;
  
  if(!data || data_sz == 0 || !key || key_sz == 0 || !out_size)
    return NULL;
    
  *out_size = 0;
  
  h_key = sha256_hash(key, key_sz, &h_sz);
  if(!h_key || h_sz == 0)
      return NULL;
      
  AES_set_encrypt_key(h_key, 256, &aes_key);
  
  padded = PKCS7_pad(data, data_sz, AES_BLOCK_SIZE, &padded_size, 1);
  if(!padded) {
      if(h_key) {
          free(h_key);
          h_key = NULL;
      }
      
      return NULL;
  }
  
  ciphertext_sz = (padded_size / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
  ciphertext = calloc(ciphertext_sz, sizeof(char));
  if(!ciphertext) {
	  if(h_key) {
	      free(h_key);
	      h_key = NULL;
	  }
	  
	  if(padded) {
	      free(padded);
	      padded = NULL;
	  }
  
	  return NULL;
  }
  
  for(int i = 0 ; i < (padded_size / AES_BLOCK_SIZE) ; i++)
      AES_ecb_encrypt(padded + (i * AES_BLOCK_SIZE), ciphertext + (i * AES_BLOCK_SIZE), &aes_key, AES_ENCRYPT);
  
  if(h_key) {
      free(h_key);
      h_key = NULL;
  }
  
  if(padded) {
      free(padded);
      padded = NULL;
  }
  
  *out_size = ciphertext_sz;

  return ciphertext;
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
  
  return channel_id;
}

int parse_socks_hdr(char *data, size_t data_sz, char **host, int **port) {
  socks_hdr *s_hdr = NULL;
  char *host_string = NULL;
  
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

  if(inet_ntop(AF_INET, &s_hdr->dstip, host_string, INET_ADDRSTRLEN) == NULL) {
     puts("err inet_ntop");
     return 0;
  }
  
  *host = host_string;
  *port = s_hdr->dstport;

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

int interpret_remote_packet(int client_id, char *data, size_t data_sz) {
  // TODO
  //    unpack structure, if client_id == 0 means command, else data to redirect to proxy srv side
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
    if(!ptr)
        return NULL;
        
    if(out_size_x == 0)
        return NULL;
        
    sol = sha256_hash(ptr, out_size_x, &s_out_size);
    if(!sol) {
        if(ptr) {
            free(ptr);
            ptr = NULL;
        }
        return NULL;
    }
        
    if(ptr) {
        free(ptr);
        ptr = NULL;
    }
    
    *out_size = s_out_size;
    return sol;
}

void generate_random_challenge(char *chall, size_t chall_sz) {
   if(!chall || chall_sz == 0)
      return;
   
   for(int i = 0 ; i < chall_sz ; i++)
       chall[i] = (rand() % (MAX_CHALL_CHR_VAL - MIN_CHALL_CHR_VAL + 1)) + MIN_CHALL_CHR_VAL;
   
   return;
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
        
    p = get_challenge_solution(chall, CHALLENGE_DEFAULT_SIZE, &out_size, key, key_sz);
    if(!p || out_size == 0) {
       err = 1;
       goto end;
    }
        
    p_clt = calloc(out_size, sizeof(char));
    if(!p_clt) {
       err = 1;
       goto end;
    }
        
    r = write(sock, chall, CHALLENGE_DEFAULT_SIZE);
    if(r <= 0) {
       err = 1;
       goto end;
    }
    
    r = read(sock, p_clt, out_size);
    if(r <= 0) {
       err = 1;
       goto end;
    }
    
    if(r != out_size) {
       err = 1;
       goto end;
    }
    
    if(memcmp(p_clt, p, out_size) != 0) {
       cid = 0;
    } else {
       cid = generate_client_id(); // TODO: also check if it already exists
       // TODO: init cid
    }
    
    r = write(sock, &cid, sizeof(uint32_t));
    if(r <= 0 || r != sizeof(uint32_t))
        return 0;
        
    if(cid == 0) {
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
  
  if(err)
    return 0;
    
  return cid;
}

int relay_tcp_srv_poll(int sock) {
  int err = 0;
  int cid = 0;
  int res = 0;
  struct pollfd fds[1] = { -1 };
  char tmp_buffer[RELAY_BUFFER_SIZE + 1] = { 0 };
  
  if(sock < 0) {
     err = 1;
     goto end;
  }
  
  if(!(cid = handshake(sock))) {
     err = 1;
     goto end;
  }

  fds[0].fd = sock;
  fds[0].events = POLLIN;
  
  while(1) {
     memset(tmp_buffer, 0, RELAY_BUFFER_SIZE);
     
     res = poll(fds, 1, -1);
     if(res == -1) {
        // TODO: mark client and its channels as close (plus close proxy srv side of each fucked channel)
        err = 1;
        goto end;
     } else if(res == 0) {
        continue;
     } else {
        if(fds[0].revents & POLLIN) {
            r = read(sockfd, tmp_buffer, RELAY_BUFFER_SIZE);
            if(r < 0) {
               // TODO: mark client and its channels as close (plus close proxy srv side of each fucked channel)
               err = 1;
               goto end;
            } else if(r == 0) { /* conn closed */
               // TODO: mark client and its channels as close (plus close proxy srv side of each fucked channel)
               err = 0;
               goto end;
            }
            
            // TODO: send the data from tmp_buffer (send it to proxy conn side): MAKE SURE TO USE r AND NOT RELAY_BUFFER_SIZE
            
        } else if((fds[0].revents & POLLHUP) != 0) { /* conn closed */
           // TODO: mark client and its channels as close (plus close proxy srv side of each fucked channel)
           err = 0;
           goto end;
        }
        
        sleep(1);
  }
  
  err = 0;
end:
  // TODO: close sock here if not already
  return 1;
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
      return -1;
    sent += r;
  }

  return sent;
}

ssize_t http_read_all(int sock, SSL *c_ssl, char **data, size_t *data_sz, int is_https) {
  int bytes_available = 0;
  size_t sent = 0;
  int r = 0;
  char *ptr = NULL;
  BIO *s_rbio = NULL;
  int s_fd = -1;
  int sock_m = -1;

  if(sock < 0 || !c_ssl || !data || !data_sz)
    return -1;

  *data = NULL;
  *data_sz = 0;

  sock_m = sock;

  // TODO: check if FIONREAD on BIO obtained fd is good
  if(is_https) {
    s_rbio = SSL_get_rbio(c_ssl);
    if(BIO_get_fd(s_rbio, &sock_m) < 0)
      return -1;
  }

  #if WINDOWS_OS
  r = ioctlsocket(sock_m, FIONREAD, &bytes_available);
  #else
  r = ioctl(sock_m, FIONREAD, &bytes_available);
  #endif
  if(r < 0)
    return -1;

  if(bytes_available < 0) {
    *data = NULL;
    *data_sz = 0;
    return 0;
  }

  ptr = calloc(bytes_available + 1, sizeof(char));
  if(!ptr)
    return -1;

  while(sent < bytes_available) {
    if(is_https)
      r = SSL_read(c_ssl, ptr, bytes_available - sent);
    else
      r = read(sock_m, ptr, bytes_available - sent);
    if(r < 0)
      return -1;
    sent += r;
  }

  *data = ptr;
  *data_sz = bytes_available;

  return sent;
}

/*
int open_http_conn(char *host, int port, int is_https, SSL **c_ssl) {
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  X509 *cert = NULL;
  X509_NAME *cert_name = NULL;
  int sock = 0;
  struct sockaddr_in srvaddr, cli;

  if(!host || port == 0 || !c_ssl)
    return -1;

  *c_ssl = NULL;

  if(is_https) {
    if(SSL_library_init() < 0)
      return -1;

    if((ctx = SSL_CTX_new(TLS_client_method())) == NULL)
      return -1;

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    ssl = SSL_new(ctx);
    if(ssl == NULL)
      return -1;
  }

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if(sock < 0)
    return -1;

  bzero(&srvaddr, sizeof(srvaddr));

  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = inet_addr(host);
  srvaddr.sin_port = htons(port);

  if(connect(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) != 0) {
    if(sock != -1)
      close(sock);
    return -1;
  }

  if(is_https) {
    SSL_set_fd(ssl, sock);

    if(SSL_connect(ssl) != 1)
      return -1;

    cert = SSL_get_peer_certificate(ssl);
    if(cert == NULL)
      return -1;

    cert_name = X509_NAME_new();
    cert_name = X509_get_subject_name(cert);

    _ssl = ssl;
    _ctx = ctx;
    _cert = cert;

    *c_ssl = ssl;
  }

  return sock;
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

  if(sock != -1)
    close(sock);

  return;
}
*/

/*
  UNKNOWN_REQUEST_TYPE = 0,
  HANDSHAKE_SESSION_TYPE,
  DATA_REQUEST_TYPE,
  DATA_SENDING_TYPE,
*/

char *interpret_http_req(char *data, size_t data_sz, size_t *out_size) {
   char *p = NULL;
   char *p1 = NULL;
   char *p2 = NULL;
   char *p3 = NULL;
   char *bk = NULL;
   char *chall = NULL;
   char *real_sol = NULL;
   size_t real_sol_sz = 0;
   int found = 0;
   int cid = 0;
   int h_id = 0;
   int err = 0;
   char *out = NULL;
   size_t osz = 0;
   char *raw = NULL'
   size_t raw_sz = 0;
   req_t req_type = UNKNOWN_REQUEST_TYPE;
   
   if(!data || data_sz == 0 || !out_size)
      return NULL;
      
   *out_size = 0;
  
   p1 = strstr(data, "?h=");
   if(p1) {
         req_type = HANDSHAKE_SESSION_TYPE;
      }
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
      *out_size = 0;
      return NULL;
   }
   
   p = memdup(data, data_sz);
   if(!p) {
     *out_size = 0;
     return NULL;
   }
   
   if(req_type == DATA_SENDING_TYPE ||
      req_type == DATA_REQUEST_TYPE) {
           bk = p2 = memdup(data, data_sz);
           if(!p2) {
              puts("fail 0");
              err = 1;
              goto end;
           }
           
           p2 = strstr(p, "?cid=");
           if(!p2) {
              puts("fail 1");
              err = 1;
              goto end;
           }
           p3 = p2 + strlen("?cid=");
           
           found = 0;
           for(int i = 0 ; i < strlen(p3) ; i++) {
              if(p3[i] == ' ') {
                 p3[i] = '\0';
                 found = 1;
                 break;
              } 
           }
           
           if(!found) {
              puts("fail 2");
              err = 1;
              goto end;
           }
           
           cid = atoi(p3);
           if(cid <= 0) {
              puts("fail 3");
              err = 1;
              goto end;
           }
           
           if(/* TODO: check if cid is NOT defined in global structs */) {
              puts("fail 4");
              err = 1;
              goto end;
           }

           if(bk) {
              free(bk);
              bk = NULL;
           }
              
           p2 = NULL;
           p3 = NULL;
           
           if(req_type == DATA_SENDING_TYPE) {
		   p2 = strstr(p, DATA_INPUT_PREFIX);
		   if(!p2) {
                      err = 1;
                      goto end;
		   }
		   p2 += sizeof(DATA_INPUT_PREFIX);
		   
		   p3 = strstr(p2, DATA_INPUT_SUFFIX);
		   if(!p3) {
                      err = 1;
                      goto end;
		   }
		   
		   *p3 = 0;
		 
		  raw = base64_decode(p2, strlen(p2), &raw_sz);
		  if(raw) {
		      err = 1;
		      goto end;
		  }
		   
		 if(!interpret_remote_packet(cid, raw, raw_sz)) {
		    err = 1;
		    goto end;
		 }
		   
		 if(raw) {
		   free(raw);
		   raw = NULL;
		 }
		 
		 if(p) {
		    free(p);
		    p = NULL;
		 }
		 
		 *out_size = 0;
		 return NULL;
	   } else if(req_type == DATA_REQUEST_TYPE) {
	   	   // TODO: [...]
	   	   //   check if we are in the process of route discovery, if so prorize it over queued buffers
	   	   //   if no discovery process currently, grab next queued buffer with that cid and return it
	   }
   } else if(req_type == HANDSHAKE_SESSION_TYPE) {
           bk = p2 = memdup(data, data_sz);
           if(!p2) {
              puts("fail 0x");
              err = 1;
              goto end;
           }
           
           p2 = strstr(p, "?h=");
           if(!p2) {
              puts("fail 1x");
              err = 1;
              goto end;
           }
           p3 = p2 + strlen("?h=");
           
           found = 0;
           for(int i = 0 ; i < strlen(p3) ; i++) {
              if(p3[i] == ' ') {
                 p3[i] = '\0';
                 found = 1;
                 break;
              } 
           }
           
           if(!found) {
              puts("fail 2x");
              err = 1;
              goto end;
           }
           
           h_id = atoi(p3);
           if(h_id < 0) {
              puts("fail 3x");
              err = 1;
              goto end;
           }

           if(bk) {
              free(bk);
              bk = NULL;
           }
              
           p2 = NULL;
           p3 = NULL;
         
         if(handshake_sess_exists(h_id)) {
            if(is_challenge_solved(h_id)) {
               // TODO: create a new client in structures
               // TODO: return uint32_t as cid to client and HTTP data with b64 blabla to caller
            } else {
		   p2 = strstr(p, DATA_INPUT_PREFIX);
		   if(!p2) {
                      err = 1;
                      goto end;
		   }
		   p2 += sizeof(DATA_INPUT_PREFIX);
		   
		   p3 = strstr(p2, DATA_INPUT_SUFFIX);
		   if(!p3) {
                      err = 1;
                      goto end;
		   }
		   
		   *p3 = 0;
		  
		  raw = base64_decode(p2, strlen(p2), &raw_sz);
		  if(raw) {
		      err = 1;
		      goto end;
		  }
		  
		  real_sol = get_h_challenge_solution(h_id, &real_sol_sz);
		  if(!real_sol) {
		    err = 1;
		    goto end;
		  }
		  
		  if(raw_sz == real_sol_sz && (memcmp(raw, real_sol, raw_sz) == 0)) {
		       puts("right sol");
		       if(!mark_challenge_solved(h_id)) {
		          err = 1;
		          goto end;
		       }
		   } else {
		      puts("wronng sol");
		   }
               
		 if(bk) {
		     free(bk);
		     bk = NULL;
		   }
		   
		   if(p) {
		      free(p);
		      p = NULL;
		   }
               
               *out_size = 0;
               return NULL;
            }
         } else {
             if(!create_handshake(h_id)) {
               err = 1;
               goto end;
             }
             
             chall = get_challenge(h_id);
             if(!chall) {
               err = 1;
               goto end;
             }
             
             // TODO: incapsulate into HTTP data and blabla base64 and return it to client
         }
   }
   
  if(p) {
    free(p);
    p = NULL;
  }
   
   // TODO: remember to return the actual HTTP data with headers, base64 encoded etc to caller (not actual binary data)!!!!!!!!!!!!!!!!!111+1
      
  err = 0;
end:
   if(bk) {
     free(bk);
     bk = NULL;
   }
   
   if(p) {
      free(p);
      p = NULL;
   }

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
     err = 1;
     goto end;
  }
  
  if(!data || data_sz == 0) {
     err = 0;
     goto end;
  }

   out = interpret_http_req(data, data_sz, &out_size);
   if(!out || out_size == 0) {
      asprintf(&out, "HTTP/1.1 200 OK\r\n"
                     "Cache-Control: private, max-age=0\r\n"
                     "Content-Type: text/html; charset=ISO-8859-1\r\n"
                     "X-XSS-Protection: 0\r\n"
                     "X-Frame-Options: SAMEORIGIN\r\n"
      		     "Transfer-Encoding: chunked\r\n"
      		     "Set-Cookie: session=jnd82Nsb2VFDJdn25sAlF6sdD47wv\r\n"
      		     "Set-Cookie: 78\r\n"
      		     "\r\n%s", "<!DOCTYPE html><html><head><title>blank</title></head><body><h1>blank page</h1></body></html>");
      out_size = strlen(out);
   }
   
  r = http_write_all(sock, c_ssl, &out, &out_size, is_https);
  if(r < 0) {
     err = 1;
     goto end;
  }
  
  err = 0;
end:
  // TODO: close c_ssl or sock connection here
  
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
   char *data = NULL;
   size_t data_sz = 0;
   int r = 0;
   int res = 0;
   char socks_hdr_buf[sizeof(socks_hdr) + 1] = { 0 };
   struct pollfd fds[1] = { -1 };
   char tmp_buffer[RELAY_BUFFER_SIZE + 1] = { 0 };
   int client_id = 0;
   int channel_id = 0;
   
   if(sock < 0) {
     err = 1;
     goto end;
   }
   
   r = read(sock, socks_hdr_buf, sizeof(socks_hdr));
   if(r < 0) {
      err = 1;
      goto end;
   }
   
   if(r != sizeof(socks_hdr)) {
      err = 1;
      goto end;
   }
   
   if(!parse_socks_hdr(sock_hdr_buf, sizeof(socks_hdr), &rhost, &rport)) {
      err = 1;
      goto end;
   }
   
   if(!rhost || rport <= 0) {
     err = 1;
     goto end;
   }
   
   printf("target is blavbla %s:%d\n", rhost, rport):
   
   channel_id = generate_channel_id(); // TODO: also check if it already exists

  // TODO: issue CHANNEL_OPEN_CMD cmd iteratively ...
  
  // TODO: if we got one of the clients, pair client_id with channel_id and create the globally accessible data structures
  
  fds[0].fd = sock;
  fds[0].events = POLLIN;
  
  while(1) {
     memset(tmp_buffer, 0, RELAY_BUFFER_SIZE);
     
     res = poll(fds, 1, -1);
     if(res == -1) {
        // TODO: issue a cmd close command
        err = 1;
        goto end;
     } else if(res == 0) {
        continue;
     } else {
        if(fds[0].revents & POLLIN) {
            r = read(sockfd, tmp_buffer, RELAY_BUFFER_SIZE);
            if(r < 0) {
               // TODO: issue a cmd close command
               err = 1;
               goto end;
            } else if(r == 0) { /* conn closed */
               // TODO: issue a cmd close command
               err = 0;
               goto end;
            }
            
            // TODO: send the data from tmp_buffer (queue it or send it to target conn)
            
        } else if((fds[0].revents & POLLHUP) != 0) { /* conn closed */
           // TODO: issue a cmd close command
           err = 0;
           goto end;
        }
        
        sleep(1);
  }
  
  err = 0;
end:
  pthread_exit(NULL);
  return;
}

void start_proxy_srv(arg_pass *arg) {
  char *proxy_host = NULL;
  int proxy_port = 0;
  struct sockaddr_in servaddr, cli;
  int sfd = 0;
  int err = 0;
  int res = 0;
  int i = 0;
  int connfd = 0;
  int z = 0;
  int idx = 0;
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
     puts("socket create fail");
        err = 1;
        goto end;
  }
   
  bzero(&servaddr, sizeof(servaddr));
  
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(proxy_port);
  
  if((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        puts("socket bind failed...");
        err = 1;
        goto end;
  }
  
  if((listen(sfd, MAX_CONCURRENT_PROXY_CLIENTS)) != 0) {
        puts("Listen failed...");
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
        goto end;
     }
     
     if(i >= MAX_CONCURRENT_PROXY_CLIENTS) {
         for(int x = 0 ; x < MAX_CONCURRENT_PROXY_CLIENTS ; x++) {
             res = pthread_kill(tid[x], 0);
             if(res == 0)
                continue;
             else if(res == ESRCH) {
                 tid[x] = 0;
                 i--;
             else {
                 puts("err checking status");
                 continue; /* err checking status */
             }
          }
             
         }
     }
     
     connfd = accept(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
     if(connfd < 0) {
        puts("failed incoming conn");
        continue;
     }
     
     puts("client connected to proxy bla bla bla!!!11");
     
     z = -1;
     while(z < MAX_CONCURRENT_PROXY_CLIENTS) {
        if(tid[z] == 0)
           break;
        z++;
     }
     
     if(z == -1) {
        puts("could not find a free spot!!!!! MAX_CONCURRENT_PROXY_CLIENTS reached");
        continue;
     }
     
     if(pthread_create(&tid[z], NULL, proxy_srv_poll, ((void *)connfd))) {
         puts("thread creat fail");
         continue;
     }
     
     i++;
  }
  
  err = 0;
end:
  z = 0;
  while(z < MAX_CONCURRENT_PROXY_CLIENTS) {
      res = pthread_cancel(tid[z]);
      if(res != 0) {
         puts("err canceling thread");
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
  
  pthread_exit(NULL);
  return;
}

int do_http_relay_srv(char *host, int port) {
  struct sockaddr_in servaddr, cli;
  int sfd = 0;
  int err = 0;
  int res = 0;
  int i = 0;
  int connfd = 0;
  int z = 0;
  int idx = 0;
  pthread_t tid[MAX_CONCURRENT_CLIENTS] = { 0 };
  rl_arg_pass *a_pass = NULL;
  int is_https = 0;
  
  if(!host || port <= 0) {
     err = 1;
     goto end;
  }
     
  sfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sfd < 0) {
     puts("socket create fail");
        err = 1;
        goto end;
  }
   
  bzero(&servaddr, sizeof(servaddr));
  
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);
  
  // TODO: apply specific things to implement HTTPS
  
  if((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        puts("socket bind failed...");
        err = 1;
        goto end;
  }
  
  if((listen(sfd, MAX_CONCURRENT_CLIENTS)) != 0) {
        puts("Listen failed...");
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
        goto end;
     }
     
     if(i >= MAX_CONCURRENT_CLIENTS) {
         for(int x = 0 ; x < MAX_CONCURRENT_CLIENTS ; x++) {
             res = pthread_kill(tid[x], 0);
             if(res == 0)
                continue;
             else if(res == ESRCH) {
                 tid[x] = 0;
                 i--;
             else {
                 puts("err checking status");
                 continue; /* err checking status */
             }
          }
             
         }
     }
     
     connfd = accept(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
     if(connfd < 0) {
        puts("failed incoming conn");
        continue;
     }
     
     puts("client connected to relay srv bla bla bla!!!11");
     
     z = -1;
     while(z < MAX_CONCURRENT_CLIENTS) {
        if(tid[z] == 0)
           break;
        z++;
     }
     
     if(z == -1) {
        puts("could not find a free spot!!!!! MAX_CONCURRENT_CLIENTS reached");
        continue;
     }
     
     a_pass = (rl_arg_pass *)calloc(1, sizeof(rl_arg_pass));
     if(!a_pass) {
        err = 1;
        goto end;
     }
     
     if(_proto == TCP_COM_PROTO) {
        err = 1;
        goto end;
     }
     
     is_https = (_proto == HTTPS_COM_PROTO) ? 1 : 0;
     
     a_pass->sock = connfd;
     a_pass->c_ssl = c_ssl;
     a_pass->is_https = is_https;
     
     if(pthread_create(&tid[z], NULL, relay_http_srv_handle_req, ((void *)a_pass))) {
         puts("thread creat fail");
         continue;
     }
     
     a_pass = NULL;
     
     i++;
  
  }
  
  err = 0;
end:
  z = 0;
  while(z < MAX_CONCURRENT_CLIENTS) {
      res = pthread_cancel(tid[z]);
      if(res != 0) {
         puts("err canceling thread");
         continue;
      }
      z++;
  }
  
  if(err) {
     close_srv = 1;
     sleep(2);
  }
  
  return (err == 0);
}

int do_tcp_relay_srv(char *host, int port) {
  struct sockaddr_in servaddr, cli;
  int sfd = 0;
  int err = 0;
  int res = 0;
  int i = 0;
  int connfd = 0;
  int z = 0;
  int idx = 0;
  pthread_t tid[MAX_CONCURRENT_CLIENTS] = { 0 };
  
  if(!host || port <= 0) {
     err = 1;
     goto end;
  }
     
  sfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sfd < 0) {
     puts("socket create fail");
        err = 1;
        goto end;
  }
   
  bzero(&servaddr, sizeof(servaddr));
  
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);
  
  if((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        puts("socket bind failed...");
        err = 1;
        goto end;
  }
  
  if((listen(sfd, MAX_CONCURRENT_CLIENTS)) != 0) {
        puts("Listen failed...");
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
        goto end;
     }
     
     if(i >= MAX_CONCURRENT_CLIENTS) {
         for(int x = 0 ; x < MAX_CONCURRENT_CLIENTS ; x++) {
             res = pthread_kill(tid[x], 0);
             if(res == 0)
                continue;
             else if(res == ESRCH) {
                 tid[x] = 0;
                 i--;
             else {
                 puts("err checking status");
                 continue; /* err checking status */
             }
          }
             
         }
     }
     
     connfd = accept(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
     if(connfd < 0) {
        puts("failed incoming conn");
        continue;
     }
     
     puts("client connected to relay srv bla bla bla!!!11");
     
     z = -1;
     while(z < MAX_CONCURRENT_CLIENTS) {
        if(tid[z] == 0)
           break;
        z++;
     }
     
     if(z == -1) {
        puts("could not find a free spot!!!!! MAX_CONCURRENT_CLIENTS reached");
        continue;
     }
     
     if(pthread_create(&tid[z], NULL, relay_tcp_srv_poll, ((void *)connfd))) {
         puts("thread creat fail");
         continue;
     }
     
     i++;
  
  }
  
  err = 0;
end:
  z = 0;
  while(z < MAX_CONCURRENT_CLIENTS) {
      res = pthread_cancel(tid[z]);
      if(res != 0) {
         puts("err canceling thread");
         continue;
      }
      z++;
  }
  
  if(err) {
     close_srv = 1;
     sleep(2);
  }
  
  return (err == 0);
}

void start_relay_srv(arg_pass *arg) {
  char *relay_host = NULL;
  int relay_port = 0;
  proto_t proto = 0;
  int r = 0;
  
  if(!arg) {
        err = 1;
        goto end;
  }
     
  relay_host = arg->host;
  relay_port = arg->port;
  proto = arg->proto;
  
  if(!relay_host || relay_port <= 0) {
        err = 1;
        goto end;
  }
  
  if(proto == TCP_COM_PROTO) {
     r = do_tcp_relay_srv(relay_host, relay_port);
  } else if(proto == HTTP_COM_PROTO ||
      proto == HTTPS_COM_PROTO) {
     r = do_http_relay_srv(relay_host, relay_port);
  } else {
      puts("unknown proto received");
      err = 1;
      goto end;
  }
  
  if(r <= 0) {
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
     
  if(pthread_create(&th, NULL, start_proxy_srv, (void *)arg))
     return 0;
     
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
  
  if(!handshake_defs) {
    handshake_defs = (http_handshake_def *)calloc(MAX_CONCURRENT_CLIENTS, sizeof(http_handshake_def));
    if(!handshake_defs)
      fail = OUT_OF_MEMORY_ERROR;
      goto end;
  }
  
  _key = memdup(key, key_sz);
  _key_sz = key_sz;
  _proto = proto;
  
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





