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
    if(!hash)
        return NULL;
       
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





