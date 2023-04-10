/*

...

TODO:
- test
- apply encryption in sending-receiving functions
- use SHA256 in the end of chall enc again

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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "tp/base64.h"

#define DEBUG 1

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

#define MIN_HANDSHAKE_SESS_ID 0x0000111111111111
#define MAX_HANDSHAKE_SESS_ID 0x0000ffffffffffff

#define AES_IV_SIZE 16

#define MIN_IV_CHAR_RANGE 0x1
#define MAX_IV_CHAR_RANGE 0xff

#define MAX_KEY_SIZE 64

#define MAX_HOSTNAME_SIZE 255

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

channel_def *global_conn = NULL;

int pending_ch_array[MAX_CONCURRENT_CHANNELS] = { 0 };

void ping_worker(void) {
  long curr_time = 0;
  
  while(1) {
    sleep(10);
    curr_time = time(NULL);
    if(srv_down) {
      pthread_exit(NULL);
      return;
    }

    if((curr_time - last_conn_time) > RELAY_TIMEOUT) {
      printf("No response from server for %ld seconds. Restarting relay...\n", RELAY_TIMEOUT);
      pthread_exit(NULL);
    }
  }
  pthread_exit(NULL);
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

ssize_t write_all(int sock, char **data, size_t *data_sz) {
  int r = 0;
  size_t sent = 0;
  char *ptr = NULL;
  size_t sz = 0;

  if(sock < 0 || !data || !data_sz)
    return -1;

  if(data && data_sz) {
    ptr = *data;
    sz = *data_sz;
  }

  while(sent < sz) {
    r = write(sock, ptr, sz - sent);
    if(r < 0)
      return -1;
    sent += r;
  }

  return sent;
}

ssize_t read_all(int sock, char **data, size_t *data_sz) {
  int bytes_available = 0;
  size_t sent = 0;
  int r = 0;
  char *ptr = NULL;

  if(sock < 0 || !data || !data_sz)
    return -1;

  *data = NULL;
  *data_sz = 0;

  #if WINDOWS_OS
  r = ioctlsocket(sock, FIONREAD, &bytes_available);
  #else
  r = ioctl(sock, FIONREAD, &bytes_available);
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
    r = read(sock, ptr, bytes_available - sent);
    if(r < 0)
      return -1;
    sent += r;
  }

  *data = ptr;
  *data_sz = bytes_available;

  return sent;
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
  if(http_str == NULL)
    return -1;

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
  if(http_sock < 0)
    return -1;

  http_req_sz = strlen(http_req);
  r = http_write_all(http_sock, c_ssl, &http_req, &http_req_sz, is_https);
  if(r < 0) {
    if(http_sock != -1)
      http_close(http_sock, c_ssl, is_https);
    return -1;
  }

  r = http_read_all(http_sock, c_ssl, &dummy_rsp, &dummy_sz, is_https);
  if(r < 0) {
    if(http_sock != -1)
      http_close(http_sock, c_ssl, is_https);
    return -1;
  }

  if(dummy_sz < strlen(OK_HTTP_RESPONSE) || memcmp(dummy_rsp, OK_HTTP_RESPONSE, strlen(OK_HTTP_RESPONSE)) != 0) {
    if(http_sock != -1)
      http_close(http_sock, c_ssl, is_https);
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
  if(http_sock < 0)
    return -1;

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

    return 0;
  }

  tmp_p = strstr(data_x, DATA_PREFIX);
  if(!tmp_p) {
    if(data_x) {
      free(data_x);
      data_x = NULL;
    }
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
    return 0;
  }

  b64_decoded = base64_decode(data_s, strlen(data_s), &b64_decoded_sz);
  if(b64_decoded) {
    if(data_x) {
      free(data_x);
      data_x = NULL;
    }
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
  } else
    return -1;

  if(r < 0)
    return -1;

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
  } else
    return -1;

  if(r < 0)
    return -1;

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
  if(sock == -1)
    return -1;

  bzero(&srvaddr, sizeof(srvaddr));

  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = inet_addr(host);
  srvaddr.sin_port = htons(port);

  if(connect(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) != 0) {
    close(sock);
    return -1;
  }

  return sock;
}

int send_cmd(char *cmd, size_t cmd_sz) {
  ssize_t r = 0;
  ssize_t rx = 0;
  char *tlv_packet = NULL;
  tlv_header *tlv_p = NULL;
  char *data_x = NULL;
  size_t data_sz_x = 0;

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
  rx = ctl_send_data(_ctl_sock, _host, _port, &data_x, &data_sz_x, _proto);
  if(rx < 0) {
    if(tlv_packet) {
      free(tlv_packet);
      tlv_packet = NULL;
    }
    return 0;
  }

  if(tlv_packet) {
    free(tlv_packet);
    tlv_packet = NULL;
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
      puts("Err.: command not found");
      return 0;
  }

  cmd_p->cmd = cmd_def_data[cmd].value;
  cmd_p->channel_id = channel_id;

  if(!send_cmd(cmd_data, cmd_data_sz)) {
    if(cmd_data) {
      free(cmd_data);
      cmd_data = NULL;
    }
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
  struct sockaddr_in srvaddr, cli;

  if(!host || port == 0)
    return 0;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if(sock == -1)
    return -1;

  bzero(&srvaddr, sizeof(srvaddr));

  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = inet_addr(host);
  srvaddr.sin_port = htons(port);

  if(connect(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) != 0) {
    close(sock);
    return -1;
  }

  pthread_mutex_lock(&glb_conn_lock);

  for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
    if(global_conn[i].channel_id == channel_id) {
      close_channel(channel_id);
    }
  }

  for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
    if(global_conn[i].channel_id == 0) {
      idx = i;
      break;
    }
  }

  if(idx == -1) {
    close(sock);
    pthread_mutex_unlock(&glb_conn_lock);
    return -1;
  }

  global_conn[idx].channel_id = channel_id;
  global_conn[idx].sock = sock;
  global_conn[idx].host = strdup(host);
  global_conn[idx].port = (uint16_t)port;

  pthread_mutex_unlock(&glb_conn_lock);

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
  if(r < 0)
    return 0;
  return 1;
}

ssize_t send_data_to_ctl_srv(char *data, size_t data_sz) {
  ssize_t rx = 0;
  char *data_x = NULL;
  size_t data_sz_x = 0;

  if(!data || data_sz == 0)
    return 0;

  data_x = data;
  data_sz_x = data_sz;

  rx = ctl_send_data(_ctl_sock, _host, _port, &data_x, &data_sz_x, _proto);
  if(rx < 0)
    return 0;

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
      if(cmd_sz < sizeof(conn_cmd))
        return 0;

      channel_id = c_data->channel_id;
      ip_addr = c_data->ip_addr;
      port = c_data->port;

      dummy_in.sin_addr.s_addr = ip_addr;

      host = inet_ntoa(dummy_in.sin_addr);
      if(!host)
        return 0;

      if(!open_channel_conn(channel_id, host, port))
        return 0;

      return 1;

   } else if(cmd_c == cmd_def_data[CHANNEL_CLOSE_CMD].value) {
      channel_id = c_data->channel_id;

      if(!close_channel(channel_id))
        return 0;

      return 1;

  } else if(cmd_c == cmd_def_data[RELAY_CLOSE_CMD].value) {
      shutdown_relay();

      return 1;

  } else if(cmd_c == cmd_def_data[PING_CMD].value) {
      last_conn_time = time(NULL);

      if(!send_remote_cmd(PING_CMD, 0))
        return 0;

      return 1;

  } else {
      puts("Unknown command received...");
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

uint32_t do_tcp_handshake(int sock, char *key, size_t key_sz) {
    int r = 0;
    char chall[CHALLENGE_DEFAULT_SIZE + 1] = { 0 };
    size_t out_size = 0;
    char *p = NULL;
    uint32_t cid = 0;
    
    if(sock < 0 || !key || key_sz == 0)
       return 0;
       
    r = read(sock, chall, CHALLENGE_DEFAULT_SIZE);
    if(r <= 0)
        return 0;
        
    if(r != CHALLENGE_DEFAULT_SIZE)
        return 0;
        
    p = get_challenge_solution(chall, CHALLENGE_DEFAULT_SIZE, &out_size, key, key_sz);
    if(!p || out_size == 0)
        return 0;
        
    r = write(sock, p, out_size);
    if(r <= 0) {
        if(p) {
            free(p);
            p = NULL;
        }
        return 0;
    }
    
    if(p) {
        free(p);
        p = NULL;
    }
    
    r = read(sock, &cid, sizeof(uint32_t));
    if(r <= 0 || r != sizeof(uint32_t))
        return 0;
        
    if(cid == 0)
        return 0;
  
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
   if(r <= 0)
       return 0;
       
   if(r_out_sz != CHALLENGE_DEFAULT_SIZE)
       return 0;
       
   s = get_challenge_solution(p, CHALLENGE_DEFAULT_SIZE, &out_size, key, key_sz);
   if(!s || out_size == 0) {
       if(p) {
          free(p);
          p = NULL;
       }
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
       return 0;
   }
   
   if(s) {
       free(s);
       s = NULL;
   }
   
   p = NULL;
   r_out_sz = 0;
   
   r = recv_http_data(host, port, &p, &r_out_sz, is_https);
   if(r <= 0)
       return 0;
       
   if(r_out_sz != sizeof(uint32_t)) {
       if(p) {
           free(p);
           p = NULL;
       }
       return 0;
   }
       
   memcpy(&cid, p, sizeof(uint32_t));
  
  return cid;
}

uint32_t handshake(int sock, char *host, int port, proto_t proto, char *key, size_t key_sz) {
  uint32_t cid = 0;
  
  if(sock < 0 || !host || port <= 0 || !key || key_sz == 0)
      return 0;
  
  pthread_mutex_lock(&glb_conn_lock);
  
  client_id = 0;
  handshake_sess_id = generate_handshake_sess_id();

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
  
  if(!host || port <= 0)
      return;

  while(1) {
    if(srv_down)
      break;

    if(!global_conn)
      return;

    sleep(6);

    memset(i_recv_buf, 0, sizeof(i_recv_buf));

    FD_ZERO(&rfds);
    FD_ZERO(&ofds);
    
    // TODO: just if TCP? 
    //FD_SET(_ctl_sock, &rfds);
    //n = 1;
    
    n = 0;

    pthread_mutex_lock(&glb_conn_lock);

    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
      if(global_conn[i].channel_id != 0 && global_conn[i].sock > 0) {
        fd_x = global_conn[i].sock;
        if(fd_x < FD_SETSIZE)
          FD_SET(fd_x, &rfds);
        n++;
      }
    }

    for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS ; x++) {
      if(pending_ch_array[x] != 0) {
        if(pending_ch_array[x] < FD_SETSIZE)
          FD_SET(pending_ch_array[x], &ofds);
      }
    }

    tv.tv_sec = 5;
    tv.tv_usec = 0;

    retval = select(1, &rfds, &ofds, NULL, &tv);
    if(retval == -1) {
      puts("select() error. Retrying...");
      pthread_mutex_unlock(&glb_conn_lock);
      continue;
    } else if(retval == 0) {
      puts("No data. Looping...");
      pthread_mutex_unlock(&glb_conn_lock);
      continue;
    }

    for(int x = 0 ; x < MAX_CONCURRENT_CHANNELS ; x++) {
      if(pending_ch_array[x] != 0) {
        if(FD_ISSET(pending_ch_array[x], &ofds)) {
          ch_id = get_channel_id_by_sock(pending_ch_array[x]);
          if(ch_id <= 0) {
            pthread_mutex_unlock(&glb_conn_lock);
            return;
          }

          r0 = recv(pending_ch_array[x], &dummy, 0, MSG_DONTWAIT);
          if(r0 < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK || errno == 10035) {
              pending_ch_array[x] = 0;

              if(!send_remote_cmd(FORWARD_CONNECTION_SUCCESS, ch_id)) {
                puts("Error sending FORWARD_CONNECTION_SUCCESS");
                pthread_mutex_unlock(&glb_conn_lock);
                return;
              }

              pthread_mutex_unlock(&glb_conn_lock);
              continue;
            }

            if(errno == ECONNREFUSED || errno == ETIMEDOUT) {
              puts("Connection problems! Marking as: FORWARD_CONNECTION_FAILURE");
            }

            if(!close_channel(ch_id)) {
              puts("Error closing channel");
              pthread_mutex_unlock(&glb_conn_lock);
              return;
            }

            pending_ch_array[x] = 0;

            if(!send_remote_cmd(FORWARD_CONNECTION_FAILURE, ch_id)) {
              puts("Error sending FORWARD_CONNECTION_FAILURE");
              pthread_mutex_unlock(&glb_conn_lock);
              return;
            }

            pthread_mutex_unlock(&glb_conn_lock);
            continue;
          }

          pending_ch_array[x] = 0;

          if(!send_remote_cmd(FORWARD_CONNECTION_SUCCESS, ch_id)) {
            puts("Error sending FORWARD_CONNECTION_SUCCESS");
            pthread_mutex_unlock(&glb_conn_lock);
            return;
          }

        }
      }
    }

    for(int i = 0 ; i < MAX_CONCURRENT_CHANNELS ; i++) {
      if(global_conn[i].channel_id != 0 && global_conn[i].sock > 0) {
        fd_x = global_conn[i].sock;
        if(fd_x < FD_SETSIZE && FD_ISSET(fd_x, &rfds)) {
          if(fd_x != _ctl_sock) {
            ch_id = get_channel_id_by_sock(fd_x);
            if(ch_id <= 0) {
              puts("channel_id not found for sock");
              pthread_mutex_unlock(&glb_conn_lock);
              return;
            }

            data_buf = calloc(sizeof(tlv_header) + RELAY_BUFFER_SIZE, sizeof(char));
            if(!data_buf) {
              pthread_mutex_unlock(&glb_conn_lock);
              return;
            }
            tlv_buf = (tlv_header *)data_buf;

            r = read(fd_x, data_buf + sizeof(tlv_header), RELAY_BUFFER_SIZE);
            if(r < 0) {
              if(data_buf) {
                free(data_buf);
                data_buf = NULL;
              }

              puts("Error reading from channel");

              if(!close_channel(ch_id)) {
                puts("Error closing channel");
                pthread_mutex_unlock(&glb_conn_lock);
                return;
              }

              if(!send_remote_cmd(FORWARD_CONNECTION_FAILURE, ch_id)) {
                puts("Error sending channel-closed cmd to server");
                pthread_mutex_unlock(&glb_conn_lock);
                return;
              }

              pthread_mutex_unlock(&glb_conn_lock);
              continue;
            }

            tlv_buf->channel_id = ch_id;
            tlv_buf->tlv_data_len = r;

            if(send_data_to_ctl_srv(data_buf, sizeof(tlv_header) + r)) {
              if(data_buf) {
                free(data_buf);
                data_buf = NULL;
              }
              pthread_mutex_unlock(&glb_conn_lock);
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

    // We check here if there is something to receive from control server
    // If 0 bytes received, means nothing was sent by the server, so
    // No commands to interpret

    rx = ctl_recv_data(_ctl_sock, host, port, &data_x, &data_sz_x, proto);
    if(rx < 0) {
      puts("Error reading from control server");
      pthread_mutex_unlock(&glb_conn_lock);
      return;
    }

    if(data_sz_x == 0) {
      puts("No data received from control server");
      pthread_mutex_unlock(&glb_conn_lock);
      continue;
    }

    if(data_sz_x < sizeof(tlv_header)) {
      puts("Error reading from control server");
      pthread_mutex_unlock(&glb_conn_lock);
      return;
    }

    memcpy(i_recv_buf, data_x, sizeof(tlv_header));

    if(recv_tlv->tlv_data_len > (data_sz_x - sizeof(tlv_header))) {
      puts("Wrong tlv_header from control server");
      pthread_mutex_unlock(&glb_conn_lock);
      return;
    }

    data_buf = calloc(recv_tlv->tlv_data_len, sizeof(char));
    if(!data_buf) {
      pthread_mutex_unlock(&glb_conn_lock);
      return;
    }

    memcpy(data_buf, data_x + sizeof(tlv_header), recv_tlv->tlv_data_len);

    if(data_x) {
      free(data_x);
      data_x = NULL;
    }

    if(data_sz_x != recv_tlv->tlv_data_len) {
      puts("WARNING: Not all data received from server-side");
    }

    if(recv_tlv->channel_id == COMMAND_CHANNEL) {
      if(!interpret_remote_cmd(data_buf, recv_tlv->tlv_data_len)) {
        if(data_buf) {
          free(data_buf);
          data_buf = NULL;
        }

        puts("error interpreting received command");
        pthread_mutex_unlock(&glb_conn_lock);
        return; 
      }
    } else {
      channel_sock = get_sock_by_channel_id(recv_tlv->channel_id);
      if(channel_sock <= 0) {
        if(data_buf) {
          free(data_buf);
          data_buf = NULL;
        }

        puts("channel was not found!");
        pthread_mutex_unlock(&glb_conn_lock);
        return;
      }

      if(!relay_data(channel_sock, data_buf, recv_tlv->tlv_data_len)) {
        if(data_buf) {
          free(data_buf);
          data_buf = NULL;
        }

        puts("Error relaying data...");
        pthread_mutex_unlock(&glb_conn_lock);
        return;
      }

      if(data_buf) {
        free(data_buf);
        data_buf = NULL;
      }
    }

    pthread_mutex_unlock(&glb_conn_lock);
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
  
  puts("Starting main loop...");
  
  consec_err = 0;

  while(1) {
    if(consec_err > 2) {
       srv_down = 1;
       sleep(2);
    }
    
    // TODO: make sure to cleanup everything before returning to caller program
    if(srv_down)
      return 0;

    if(proto == TCP_COM_PROTO) {
      ctl_sock = connect_ctl_srv(host, port);
      if(ctl_sock < 0) {
        puts("Error connecting to server. Retrying...");
        consec_err++;
        sleep(10);
        continue;
      }
    } else
      ctl_sock = MAGIC_DUMMY_FD;

    // negotiate client_id with HTTP(S) or TCP
    if(!handshake(ctl_sock, host, port, proto, key, key_sz)) {
      close_wrp(ctl_sock);
      if(proto == HTTPS_COM_PROTO)
        destroy_ssl();
      return 0;
    }

    printf("Connection succeeded with: %s:%d\n", host, port);

    _host = strdup(host);
    _port = port;
    _ctl_sock = ctl_sock;
    _proto = proto;
    _key = memdup(key, key_sz);
    _key_sz = key_sz;

    puts("Starting ping worker...");
    __ping_worker();

    puts("Starting relay poll...");
    relay_poll(host, port, proto);

    if(srv_down)
      return 0;

    sleep(10);
  }

  if(proto == HTTPS_COM_PROTO)
    destroy_ssl();

  return 1;
}

#define PSK "p@ssw0rd_3241!!=#"

int main(void) {
  puts("Starting relay conn...");
  if(!start_relay_conn("127.0.0.1", 9991, HTTPS_COM_PROTO, PSK, strlen(PSK))) {
    puts("Unknown error occurred");
    return 1;
  }
  return 0;
}




