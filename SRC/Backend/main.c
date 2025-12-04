#include <stdio.h>
#include <string.h>
#include "manager.h"

int main(void)
{
    User users[MAX_USERS];
    memset(users, 0, sizeof(users));

    int user_count = 0;
    int option;

    printf("\n========================================\n");
    printf("         Welcome to KeyCheeky\n");
    printf("   Your Secure Multi-User Password Vault\n");
    printf("========================================\n");

    while (1)
    {
        printf("\n=== KeyCheeky Main Menu ===\n");
        printf("1. Sign up (Create Account)\n");
        printf("2. Login\n");
        printf("3. Exit KeyCheeky\n");
        printf("Choose an option: ");

        if (scanf("%d", &option) != 1)
        {
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
            {
            }
            printf("Invalid input. Try again.\n");
            continue;
        }

        int c;
        while ((c = getchar()) != '\n' && c != EOF)
        {
        }

        if (option == 1)
        {
            signup(users, &user_count);
        }
        else if (option == 2)
        {
            int idx = login(users, user_count);
            if (idx >= 0)
            {
                printf("\n=== Logged into KeyCheeky as %s ===\n", users[idx].username);
                userMenu(&users[idx]);
            }
        }
        else if (option == 3)
        {
            printf("\nThank you for using KeyCheeky!\n");
            printf("Goodbye!\n");
            break;
        }
        else
        {
            printf("Invalid option. Please choose 1–3.\n");
        }
    }

    return 0;
}