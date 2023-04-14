/*

*/

#define AES_IV_SIZE 16

#define MAX_KEY_SIZE 64

#define CHALLENGE_DEFAULT_SIZE 64

#define MIN_IV_CHAR_RANGE 0x1
#define MAX_IV_CHAR_RANGE 0xff

char *generate_random_iv(size_t *out_sz);
size_t get_decrypted_size(char *enc, size_t enc_sz);
char *sha256_hash(char *data, size_t size, size_t *out_sz);
char *PKCS7_pad(char *data, size_t data_sz, int bs, size_t *out_size, int is_chall);
char *PKCS7_unpad(char *data, size_t data_sz, int bs, size_t *out_size, int is_chall);
char *encrypt_data(char *data, size_t data_sz, char *key, size_t key_sz, size_t *out_size);
char *decrypt_data(char *data, size_t data_sz, char *key, size_t key_sz, size_t *out_size);
char *encrypt_challenge(char *data, size_t data_sz, char *key, size_t key_sz, size_t *out_size);

