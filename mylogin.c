#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pwdblib.h" 
#include <crypt.h>

#define USERNAME_SIZE (32)
#define NOUSER (-1)

int authenticate_user(const char *username, const char *password) {
    struct pwdb_passwd *p = pwdb_getpwnam(username);
    if (p != NULL ) {
        char *encrypted = crypt(password, p->pw_passwd); // Use the hashed password as the salt
        // print both the encrypted and the stored password
        // printf("Encrypted: %s\n", encrypted);
        // printf("Stored: %s\n", p->pw_passwd);

        if (encrypted != NULL && strcmp(encrypted, p->pw_passwd) == 0) {
            return 0; // Success
        }
    }
    return NOUSER; // Failure
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
            printf("User authenticated successfully\n");
            break; 
        } else {
            printf("Unknown user or incorrect password.\n");
        }
    }

    return 0;
}
