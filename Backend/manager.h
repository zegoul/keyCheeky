#ifndef MANAGER_H
#define MANAGER_H

#include <stdio.h>

#define MAX_USERS 8
#define MAX_CREDS_PER_USER 20
#define STRLEN 50
#define XOR_KEY 5

/* Credential struct (website + encrypted userid/password) */
typedef struct {
    char website[STRLEN];
    char userid[STRLEN];    /* stored encrypted */
    char password[STRLEN];  /* stored encrypted */
} Credential;

/* User struct: username + encrypted password + their credentials */
typedef struct {
    char username[STRLEN];
    char password[STRLEN];           /* stored encrypted */
    Credential creds[MAX_CREDS_PER_USER];
    int cred_count;
    int used;                        /* 0 = unused slot, 1 = occupied */
} User;

/* prototypes */
void xorEncrypt(char *s);
void readLine(char *buf, int size);

int findUserIndex(User users[], int user_count, const char *username);
int signup(User users[], int *user_count);
int login(User users[], int user_count);

void addCredential(User *u);
void listWebsites(User *u);
void viewCredential(User *u);
void showEncrypted(User *u);

void userMenu(User *u);

#endif /* MANAGER_H */
