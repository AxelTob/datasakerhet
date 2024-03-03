#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pwdblib.h" 
#include <crypt.h>

#define MAX_FAILED_ATTEMPTS 5
#define MAX_AGE 10


#define USERNAME_SIZE (32)
#define NOUSER (-1)

int authenticate_user(const char *username, const char *password) {
    struct pwdb_passwd *user_record = pwdb_getpwnam(username);
    if (user_record == NULL) {
        printf("Unknown user or incorrect password.\n");
        return -1; // User not found
    }

    char *encrypted = crypt(password, user_record->pw_passwd);
    if (strcmp(encrypted, user_record->pw_passwd) == 0) { // Successful login
        if (user_record->pw_failed >= MAX_FAILED_ATTEMPTS) {
            printf("Account is locked.\n");
            return -1; // Account is locked
        }
        user_record->pw_failed = 0; // Reset failed login attempts
        user_record->pw_age += 1; // Increase login age
        if (user_record->pw_age > MAX_AGE) {
            printf("Please consider changing your password.\n");
        }
        return 0; // Success
    } else { // Failed login
        user_record->pw_failed += 1;
        if (user_record->pw_failed >= MAX_FAILED_ATTEMPTS) {
            printf("Account is locked due to too many failed attempts.\n");
        } else {
            printf("Unknown user or incorrect password.\n");
        }
    }

    // Update the user record in pwfile
    if (pwdb_update_user(user_record) != 0) {
        printf("Failed to update user record.\n");
        return -1;
    }

    return -1;
}

void read_username(char *username) {
    printf("login: ");
    fgets(username, USERNAME_SIZE, stdin);
    username[strlen(username) - 1] = '\0'; // remove the newline
}

int main() {
    char username[USERNAME_SIZE];
    char *password;

    while (1) {
        read_username(username);
        password = getpass("Password: "); 
        if (authenticate_user(username, password) == 0) {
            break; 
        }
    }

    return 0;
}
