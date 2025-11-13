
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define DB_PATH "keycheeky.db"
#define AES_KEY_LEN 32
#define AES_IV_LEN 16

static int open_db(sqlite3 **db)
{
    return sqlite3_open(DB_PATH, db);
}

static int init_db()
{
    sqlite3 *db;
    if (open_db(&db))
        return 1;
    const char *sql = "CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, name TEXT, username TEXT, password BLOB, algo INTEGER, iv BLOB);";
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, 0, 0, &err);
    if (err)
        sqlite3_free(err);
    sqlite3_close(db);
    return rc;
}

static int insert_record(const char *name, const char *username, const unsigned char *password, int passlen, int algo, const unsigned char *iv, int ivlen)
{
    sqlite3 *db;
    if (open_db(&db))
        return 1;
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO accounts (name, username, password, algo, iv) VALUES (?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, password, passlen, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, algo);
    sqlite3_bind_blob(stmt, 5, iv, ivlen, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : 1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

static int fetch_record_by_name(const char *name, unsigned char **outpass, int *outlen, int *outalgo, unsigned char **outiv, int *outivlen, char **outusername)
{
    sqlite3 *db;
    if (open_db(&db))
        return 1;
    sqlite3_stmt *stmt;
    const char *sql = "SELECT username, password, algo, iv FROM accounts WHERE name = ? LIMIT 1;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 2;
    }
    const unsigned char *blob = sqlite3_column_blob(stmt, 1);
    int blen = sqlite3_column_bytes(stmt, 1);
    int algo = sqlite3_column_int(stmt, 2);
    const unsigned char *iv = sqlite3_column_blob(stmt, 3);
    int ivlen = sqlite3_column_bytes(stmt, 3);
    const unsigned char *username = sqlite3_column_text(stmt, 0);
    *outpass = malloc(blen);
    memcpy(*outpass, blob, blen);
    *outlen = blen;
    *outalgo = algo;
    *outiv = malloc(ivlen);
    memcpy(*outiv, iv, ivlen);
    *outivlen = ivlen;
    *outusername = strdup((const char *)username);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

/* AES-256-CBC encrypt/decrypt using OpenSSL EVP */
static int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char **ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int len;
    int ciphertext_len;
    *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!*ciphertext)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return -1;
    }
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return -1;
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

static int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char **plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int len;
    int plaintext_len;
    *plaintext = malloc(ciphertext_len);
    if (!*plaintext)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/* Simple XOR cipher (for demonstration - NOT secure) */
static int xor_encrypt(const unsigned char *in, int inlen, const unsigned char *key, int keylen, unsigned char **out)
{
    *out = malloc(inlen);
    if (!*out)
        return -1;
    for (int i = 0; i < inlen; i++)
        (*out)[i] = in[i] ^ key[i % keylen];
    return inlen;
}
static int xor_decrypt(const unsigned char *in, int inlen, const unsigned char *key, int keylen, unsigned char **out)
{
    return xor_encrypt(in, inlen, key, keylen, out);
}

/* Vigenere-like (byte-wise) */
static int vig_encrypt(const unsigned char *in, int inlen, const unsigned char *key, int keylen, unsigned char **out)
{
    *out = malloc(inlen);
    if (!*out)
        return -1;
    for (int i = 0; i < inlen; i++)
        (*out)[i] = (in[i] + key[i % keylen]) & 0xFF;
    return inlen;
}
static int vig_decrypt(const unsigned char *in, int inlen, const unsigned char *key, int keylen, unsigned char **out)
{
    *out = malloc(inlen);
    if (!*out)
        return -1;
    for (int i = 0; i < inlen; i++)
        (*out)[i] = (in[i] - key[i % keylen]) & 0xFF;
    return inlen;
}

/* Base64 encode/decode using OpenSSL BIO */
#include <openssl/bio.h>
#include <openssl/buffer.h>

static char *base64_encode(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);
    return buff;
}
static unsigned char *base64_decode(const char *input, int *outlen)
{
    BIO *b64, *bmem;
    int input_len = strlen(input);
    unsigned char *buffer = malloc(input_len);
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf((void *)input, input_len);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    *outlen = BIO_read(bmem, buffer, input_len);
    BIO_free_all(bmem);
    return buffer;
}

/* Helper: constant app key (in production, Derive from master password) */
static void derive_app_key(unsigned char *key, unsigned char *iv)
{
    const char *master = "KeyCheekyMasterKey_UseBetterKeyInProd!";
    unsigned char hash[32];
    memset(hash, 0, 32);
    for (int i = 0; i < 32 && master[i]; i++)
        hash[i] = master[i];
    memcpy(key, hash, 32);
    RAND_bytes(iv, AES_IV_LEN);
}

/* CGI helpers to parse simple POST form data (application/x-www-form-urlencoded) */
static char *read_stdin_data()
{
    char *lenstr = getenv("CONTENT_LENGTH");
    if (!lenstr)
        return NULL;
    int len = atoi(lenstr);
    char *buf = malloc(len + 1);
    if (!buf)
        return NULL;
    if (fread(buf, 1, len, stdin) != len)
    {
        free(buf);
        return NULL;
    }
    buf[len] = 0;
    return buf;
}

static void url_decode(char *src)
{
    char *dst = src;
    char hex[3] = {0};
    while (*src)
    {
        if (*src == '+')
        {
            *dst++ = ' ';
            src++;
        }
        else if (*src == '%' && src[1] && src[2])
        {
            hex[0] = src[1];
            hex[1] = src[2];
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        }
        else
            *dst++ = *src++;
    }
    *dst = 0;
}

static void get_field(char *data, const char *name, char *out, int outlen)
{
    char *p = strstr(data, name);
    if (!p)
    {
        out[0] = 0;
        return;
    }
    p = strchr(p, '=');
    if (!p)
    {
        out[0] = 0;
        return;
    }
    p++;
    char *end = strchr(p, '&');
    int l = end ? (end - p) : strlen(p);
    if (l >= outlen)
        l = outlen - 1;
    strncpy(out, p, l);
    out[l] = 0;
    url_decode(out);
}

/* Main CGI entry: supports action=add or action=view */
int main(void)
{
    init_db();
    printf("Content-Type: text/plain\r\n\r\n");
    char *data = read_stdin_data();
    if (!data)
    {
        printf("No data received\n");
        return 0;
    }
    char action[64];
    action[0] = 0;
    get_field(data, "action", action, 64);
    if (strcmp(action, "add") == 0)
    {
        char name[256], username[256], password[1024], algo_s[8];
        get_field(data, "name", name, 256);
        get_field(data, "username", username, 256);
        get_field(data, "password", password, 1024);
        get_field(data, "algo", algo_s, 8);
        int algo = atoi(algo_s);
        unsigned char appkey[AES_KEY_LEN];
        unsigned char iv[AES_IV_LEN];
        derive_app_key(appkey, iv);
        unsigned char *enc = NULL;
        int enclen = 0;
        if (algo == 1)
            enclen = aes_encrypt((unsigned char *)password, strlen(password), appkey, iv, &enc);
        else if (algo == 2)
            enclen = xor_encrypt((unsigned char *)password, strlen(password), appkey, AES_KEY_LEN, &enc);
        else if (algo == 3)
            enclen = vig_encrypt((unsigned char *)password, strlen(password), appkey, AES_KEY_LEN, &enc);
        else
        {
            enclen = aes_encrypt((unsigned char *)password, strlen(password), appkey, iv, &enc);
        }
        if (enclen < 0)
        {
            printf("Encryption failed\n");
            free(data);
            return 0;
        }
        insert_record(name, username, enc, enclen, algo, iv, AES_IV_LEN);
        free(enc);
        printf("OK\n");
    }
    else if (strcmp(action, "view") == 0)
    {
        char name[256];
        get_field(data, "name", name, 256);
        unsigned char *stored = NULL;
        int storedlen = 0;
        int algo = 0;
        unsigned char *iv = NULL;
        int ivlen = 0;
        char *username = NULL;
        if (fetch_record_by_name(name, &stored, &storedlen, &algo, &iv, &ivlen, &username) != 0)
        {
            printf("Not found\n");
            free(data);
            return 0;
        }
        unsigned char appkey[AES_KEY_LEN];
        unsigned char dummyiv[AES_IV_LEN];
        memset(dummyiv, 0, AES_IV_LEN);
        derive_app_key(appkey, dummyiv);
        unsigned char *dec = NULL;
        int declen = 0;
        if (algo == 1)
            declen = aes_decrypt(stored, storedlen, appkey, iv, &dec);
        else if (algo == 2)
            declen = xor_decrypt(stored, storedlen, appkey, AES_KEY_LEN, &dec);
        else if (algo == 3)
            declen = vig_decrypt(stored, storedlen, appkey, AES_KEY_LEN, &dec);
        else
            declen = aes_decrypt(stored, storedlen, appkey, iv, &dec);
        if (declen < 0)
        {
            printf("Decryption failed\n");
            free(stored);
            free(iv);
            free(username);
            free(data);
            return 0;
        }
        dec[declen] = 0;
        printf("username=%s\npassword=%s\n", username, (char *)dec);
        free(stored);
        free(iv);
        free(username);
        free(dec);
    }
    else
    {
        printf("Unknown action\n");
    }
    free(data);
    return 0;
}
