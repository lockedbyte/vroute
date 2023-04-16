/*

*/

#ifndef HEXDUMP_COLS
    #define HEXDUMP_COLS 16
#endif

int file_exists(const char *path);
void __hexdump(const char *func_name, char *tag, void *mem, size_t len);
void *memdup(const void *mem, size_t size);
ssize_t write_all(int sock, char **data, size_t *data_sz);
ssize_t read_all(int sock, char **data, size_t *data_sz);





