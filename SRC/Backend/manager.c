#include <stdio.h>
#include <string.h>
#include "manager.h"

void xorEncrypt(char *s)
{
    for (int i = 0; s[i] != '\0'; i++)
    {
        s[i] ^= XOR_KEY;
    }
}

void readLine(char *buf, int size)
{
    if (fgets(buf, size, stdin) != NULL)
    {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
    }
    else
    {
        buf[0] = '\0';
    }
}

int findUserIndex(User users[], int user_count, const char *username)
{
    for (int i = 0; i < user_count; i++)
    {
        if (users[i].used && strcmp(users[i].username, username) == 0)
            return i;
    }
    return -1;
}

int signup(User users[], int *user_count)
{
    if (*user_count >= MAX_USERS)
    {
        printf("User storage full (max %d users).\n", MAX_USERS);
        return -1;
    }

    char username[STRLEN], password[STRLEN];

    printf("Choose a username: ");
    readLine(username, STRLEN);

    if (strlen(username) == 0)
    {
        printf("Username cannot be empty.\n");
        return -1;
    }

    if (findUserIndex(users, *user_count, username) != -1)
    {
        printf("Username '%s' already exists. Pick another.\n", username);
        return -1;
    }

    printf("Choose a password: ");
    readLine(password, STRLEN);

    if (strlen(password) == 0)
    {
        printf("Password cannot be empty.\n");
        return -1;
    }

    int slot = -1;
    for (int i = 0; i < MAX_USERS; i++)
    {
        if (!users[i].used)
        {
            slot = i;
            break;
        }
    }
    if (slot == -1)
    {
        printf("No free user slot found (unexpected).\n");
        return -1;
    }

    strncpy(users[slot].username, username, STRLEN);
    users[slot].username[STRLEN - 1] = '\0';

    /* store encrypted password */
    strncpy(users[slot].password, password, STRLEN);
    users[slot].password[STRLEN - 1] = '\0';
    xorEncrypt(users[slot].password);

    users[slot].cred_count = 0;
    users[slot].used = 1;

    (*user_count)++;
    printf("Signup successful. You can now login as '%s'.\n", username);
    return slot;
}

int login(User users[], int user_count)
{
    char username[STRLEN], password[STRLEN];

    printf("Username: ");
    readLine(username, STRLEN);
    printf("Password: ");
    readLine(password, STRLEN);

    int idx = findUserIndex(users, user_count, username);
    if (idx == -1)
    {
        printf("No such user '%s'.\n", username);
        return -1;
    }

    char encrypted_input[STRLEN];
    strncpy(encrypted_input, password, STRLEN);
    encrypted_input[STRLEN - 1] = '\0';
    xorEncrypt(encrypted_input);

    if (strcmp(encrypted_input, users[idx].password) == 0)
    {
        printf("Login successful. Welcome, %s!\n", users[idx].username);
        return idx;
    }
    else
    {
        printf("Wrong password.\n");
        return -1;
    }
}

void addCredential(User *u)
{
    if (u->cred_count >= MAX_CREDS_PER_USER)
    {
        printf("Credential storage full for this user (max %d).\n", MAX_CREDS_PER_USER);
        return;
    }
    char website[STRLEN], userid[STRLEN], password[STRLEN];

    printf("Enter website name: ");
    readLine(website, STRLEN);
    if (strlen(website) == 0)
    {
        printf("Website cannot be empty.\n");
        return;
    }

    for (int i = 0; i < u->cred_count; i++)
    {
        if (strcmp(u->creds[i].website, website) == 0)
        {
            printf("An entry for '%s' already exists for this user.\n", website);
            return;
        }
    }

    printf("Enter user ID: ");
    readLine(userid, STRLEN);
    printf("Enter password: ");
    readLine(password, STRLEN);

    Credential *c = &u->creds[u->cred_count];
    strncpy(c->website, website, STRLEN);
    c->website[STRLEN - 1] = '\0';

    strncpy(c->userid, userid, STRLEN);
    c->userid[STRLEN - 1] = '\0';
    xorEncrypt(c->userid);

    strncpy(c->password, password, STRLEN);
    c->password[STRLEN - 1] = '\0';
    xorEncrypt(c->password);

    u->cred_count++;
    printf("Credential for '%s' saved (encrypted).\n", website);
}

void listWebsites(User *u)
{
    if (u->cred_count == 0)
    {
        printf("No saved credentials.\n");
        return;
    }
    printf("Saved websites for %s:\n", u->username);
    for (int i = 0; i < u->cred_count; i++)
    {
        printf(" - %s\n", u->creds[i].website);
    }
}

void viewCredential(User *u)
{
    if (u->cred_count == 0)
    {
        printf("No saved credentials.\n");
        return;
    }
    char website[STRLEN];
    printf("Enter website to view: ");
    readLine(website, STRLEN);

    int found = -1;
    for (int i = 0; i < u->cred_count; i++)
    {
        if (strcmp(u->creds[i].website, website) == 0)
        {
            found = i;
            break;
        }
    }
    if (found == -1)
    {
        printf("No credential found for '%s'.\n", website);
        return;
    }

    char uid[STRLEN], pass[STRLEN];
    strncpy(uid, u->creds[found].userid, STRLEN);
    uid[STRLEN - 1] = '\0';
    strncpy(pass, u->creds[found].password, STRLEN);
    pass[STRLEN - 1] = '\0';

    xorEncrypt(uid);
    xorEncrypt(pass);

    printf("\nWebsite : %s\nUser ID : %s\nPassword: %s\n", u->creds[found].website, uid, pass);
}

void showEncrypted(User *u)
{
    if (u->cred_count == 0)
    {
        printf("No saved credentials.\n");
        return;
    }
    printf("Encrypted entries for %s:\n", u->username);
    for (int i = 0; i < u->cred_count; i++)
    {
        printf("\nWebsite: %s\nEncrypted UserID: %s\nEncrypted Password: %s\n",
               u->creds[i].website, u->creds[i].userid, u->creds[i].password);
    }
}

void userMenu(User *u)
{
    while (1)
    {
        printf("\n-- Password Manager (user: %s) --\n", u->username);
        printf("1. Add credential\n");
        printf("2. List websites\n");
        printf("3. View credential (decrypted)\n");
        printf("4. Show encrypted entries (debug)\n");
        printf("5. Logout\n");
        printf("Choose option: ");

        int choice;
        if (scanf("%d", &choice) != 1)
        {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF)
            {
            }
            printf("Invalid input. Try again.\n");
            continue;
        }
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF)
        {
        }

        if (choice == 1)
            addCredential(u);
        else if (choice == 2)
            listWebsites(u);
        else if (choice == 3)
            viewCredential(u);
        else if (choice == 4)
            showEncrypted(u);
        else if (choice == 5)
        {
            printf("Logging out %s...\n", u->username);
            break;
        }
        else
        {
            printf("Pick 1..5\n");
        }
    }
}
