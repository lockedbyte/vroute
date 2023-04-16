/*

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#if DEBUG

#define VR_LOG(...) vr_log_c(__func__, __VA_ARGS__)
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

#if DEBUG

void vr_log_c(const char *func_name, log_level_t log_level, const char *format_str, ...) {
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

    SHA256((const unsigned char *)data, size, hash_fixed);

    hash = memdup(hash_fixed, SHA256_DIGEST_LENGTH);
    if(!hash)
        return NULL;
       
    *out_sz = SHA256_DIGEST_LENGTH;

    return hash;
}

char *PKCS7_pad(char *data, size_t data_sz, int block_size, size_t *out_size) {
    char *p = NULL;
    size_t pad_size = 0;
    
    if(!data || block_size < 0 || !out_size)
        return NULL;
        
    *out_size = 0;
        
    if(data_sz == 0) {
        *out_size = block_size;
        
        p = calloc(block_size, sizeof(char));
        if(!p)
            return NULL;
            
        return p;
    }
    
    pad_size = block_size - (data_sz % block_size);
    
    *out_size = data_sz + pad_size;
    
    p = calloc((data_sz + pad_size), sizeof(char));
    if(!p)
        return NULL;
        
    memcpy(p, data, data_sz);
    memset(p + data_sz, pad_size, pad_size);
    
    return p;
}

char *PKCS7_unpad(char *data, size_t data_sz, int block_size, size_t *out_size) {
    char *p = NULL;
    char pad_value = 0;

    if(!data || block_size < 0 || !out_size)
        return NULL;
        
    *out_size = 0;

    if((data_sz % block_size) != 0 || data_sz == 0) {
        *out_size = 0;
        VR_LOG(LOG_ERROR, "Error: data size not AES_BLOCK_SIZE-aligned for unpadding...");
        return NULL;
    }
    
    pad_value = data[data_sz - 1];
    if (pad_value == 0 || pad_value > block_size) {
        *out_size = 0;
        VR_LOG(LOG_ERROR, "Last value for padding is wrong, corrupted data stream or non-padded data provided...");
        return NULL;
    }
    
    for (size_t i = data_sz - pad_value ; i < data_sz ; i++) {
        if (data[i] != pad_value) {
            *out_size = 0;
            VR_LOG(LOG_ERROR, "Invalid pad value, corrupted data stream or non-padded data provided...");
            return NULL;
        }
    }
    
    *out_size = data_sz - pad_value;
    
    p = calloc((data_sz - pad_value), sizeof(char));
    if(!p)
        return NULL;
        
    memcpy(p, data, (data_sz - pad_value));
    
    return p;
}

#if 0
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
#endif

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
    char *iv_bak = NULL;
  
    if(!data || data_sz == 0 || !key || key_sz == 0 || !out_size)
        return NULL;
    
    *out_size = 0;
  
    h_key = sha256_hash(key, key_sz, &h_sz);
    if(!h_key || h_sz == 0) {
        VR_LOG(LOG_ERROR, "Error trying to hash key with SHA-256");
        return NULL;
    }
    
    hexdump("cleartext data", data, data_sz);
      
    AES_set_encrypt_key((unsigned char *)h_key, 256, &aes_key);
  
    iv = generate_random_iv(&out_iv_sz);
    if(!iv || out_iv_sz != AES_IV_SIZE) {
        if(h_key) {
            free(h_key);
            h_key = NULL;
        }
        VR_LOG(LOG_ERROR, "Error generating random IV");
        return NULL;
    }
    
    iv_bak = memdup(iv, AES_IV_SIZE);
    if(!iv_bak) {
        if(h_key) {
            free(h_key);
            h_key = NULL;
        }
        return NULL;
    }
    
    hexdump("AES CBC IV", iv, out_iv_sz);
  
    padded = PKCS7_pad(data, data_sz, AES_BLOCK_SIZE, &padded_size);
    if(!padded) {
        if(h_key) {
            free(h_key);
            h_key = NULL;
        }

        if(iv) {
            free(iv);
            iv = NULL;
        }
        
        if(iv_bak) {
            free(iv_bak);
            iv_bak = NULL;
        }
        VR_LOG(LOG_ERROR, "Error PKCS7-padding...");
        return NULL;
    }
    
    hexdump("padded data", padded, padded_size);
  
    ciphertext_sz = padded_size; //(padded_size / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    ciphertext = calloc(AES_IV_SIZE + padded_size, sizeof(char));
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
        
        if(iv_bak) {
            free(iv_bak);
            iv_bak = NULL;
        }
	  
        return NULL;
    }
  
    AES_cbc_encrypt((unsigned char *)padded, (unsigned char *)(ciphertext + AES_IV_SIZE), padded_size, &aes_key, (unsigned char *)iv_bak, AES_ENCRYPT);
    
    memcpy(ciphertext, iv, AES_IV_SIZE);
  
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
    
    if(iv_bak) {
        free(iv_bak);
        iv_bak = NULL;
    }
    
    hexdump("encrypted data", ciphertext, AES_IV_SIZE + ciphertext_sz);
  
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
    
    hexdump("encrypted data", data, data_sz);
  
    cleartext_sz = data_sz; //get_decrypted_size(data + AES_IV_SIZE, data_sz - AES_IV_SIZE);
   /* if(cleartext_sz == 0) {
        VR_LOG(LOG_ERROR, "Error: cleartext size is 0");
        return NULL;
    }*/

    h_key = sha256_hash(key, key_sz, &h_sz);
    if(!h_key || h_sz == 0) {
        VR_LOG(LOG_ERROR, "Error trying to hash key with SHA-256");
        return NULL;
    }
      
    AES_set_decrypt_key((unsigned char *)h_key, 256, &aes_key);
  
    iv = memdup(data, AES_IV_SIZE);
    if(!iv) {
        if(h_key) {
            free(h_key);
            h_key = NULL;
        }
        return NULL;
    }
    
    hexdump("AES CBC IV", iv, AES_IV_SIZE);
  
    cleartext = calloc(data_sz, sizeof(char));
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
  
    AES_cbc_encrypt((unsigned char *)(data + AES_IV_SIZE), (unsigned char *)cleartext, data_sz - AES_IV_SIZE, &aes_key, (unsigned char *)iv, AES_DECRYPT);
  
    if(iv) {
        free(iv);
        iv = NULL;
    }
  
    if(h_key) {
        free(h_key);
        h_key = NULL;
    }
    
    // XXX: make sure about this (TODO)
    cleartext_sz = cleartext_sz - AES_BLOCK_SIZE;
    
    hexdump("padded data", cleartext, cleartext_sz);
    
    unpadded = PKCS7_unpad(cleartext, cleartext_sz, AES_BLOCK_SIZE, &unpadded_size);
    if(!unpadded) {
        if(cleartext) {
            free(cleartext);
            cleartext = NULL;
        }
        VR_LOG(LOG_ERROR, "Error trying to PKCS7-unpad");
        return NULL;
    }
    
    hexdump("unpadded data", unpadded, unpadded_size);
  
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
    char *ciphertext = NULL;
    size_t ciphertext_sz = 0;
    char *padded = NULL;
    size_t padded_size = 0;
  
    if(!data || data_sz == 0 || !key || key_sz == 0 || !out_size)
        return NULL;
    
    *out_size = 0;
  
    h_key = sha256_hash(key, key_sz, &h_sz);
    if(!h_key || h_sz == 0) {
        VR_LOG(LOG_ERROR, "Error trying to hash key with SHA-256");
        return NULL;
    }
      
    AES_set_encrypt_key((unsigned char *)h_key, 256, &aes_key);
    
    hexdump("challenge", data, data_sz);
  
    padded = PKCS7_pad(data, data_sz, AES_BLOCK_SIZE, &padded_size);
    if(!padded) {
        if(h_key) {
            free(h_key);
            h_key = NULL;
        }
        VR_LOG(LOG_ERROR, "Error when PKCS7-padding");
        return NULL;
    }
    
    hexdump("padded challenge", padded, padded_size);
  
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
        AES_ecb_encrypt((unsigned char *)(padded + (i * AES_BLOCK_SIZE)),
                         (unsigned char *)(ciphertext + (i * AES_BLOCK_SIZE)), &aes_key, AES_ENCRYPT);
        
    hexdump("encrypted challenge", ciphertext, ciphertext_sz);
  
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





