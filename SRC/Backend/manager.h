#ifndef MANAGER_H
#define MANAGER_H

#include <stdio.h>

#define MAX_USERS 8
#define MAX_CREDS_PER_USER 20
#define STRLEN 50
#define XOR_KEY 5

typedef struct
{
    char website[STRLEN];
    char userid[STRLEN];
    char password[STRLEN];
} Credential;

typedef struct
{
    char username[STRLEN];
    char password[STRLEN];
    Credential creds[MAX_CREDS_PER_USER];
    int cred_count;
    int used;
} User;

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

#endif