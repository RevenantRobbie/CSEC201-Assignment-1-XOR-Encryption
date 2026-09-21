#include <stdio.h>
#include <stdlib.h>

void xorEncryptDecrypt(char* data, const char* key) {
    int keyLen = 0;
    while (key[keyLen] != '\0') {
        keyLen++;
    }

    for (int i = 0; data[i] != '\0'; i++) {
        data[i] ^= key[i % keyLen];
    }
}

void encrypt(char* filename, char* message, const char* key) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Error opening file for writing.\n");
        return;
    }

    xorEncryptDecrypt(message, key);
    fwrite(message, sizeof(char), strlen(message), file);

    fclose(file);
}

void decrypt(char* filename, const char* key) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Error opening file for reading.\n");
        return;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* data = (char*)malloc((fileSize + 1) * sizeof(char));
    if (data == NULL) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return;
    }

    fread(data, sizeof(char), fileSize, file);
    data[fileSize] = '\0';

    xorEncryptDecrypt(data, key);

    for (int i = 0; data[i] != '\0'; i++) {
        printf("%c", data[i]);
    }
    printf("\n");

    free(data);
    fclose(file);
}

int main() {
    char choice;
    printf("Do you want to encrypt or decrypt? (e/d): ");
    scanf(" %c", &choice);
    getchar();

    if (choice == 'e') {
        char filename[100];
        char message[256];
        char key[32];

        printf("Enter the filename: ");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\n")] = '\0';

        printf("Enter the message to encrypt: ");
        fgets(message, sizeof(message), stdin);

        printf("Enter the encryption key: ");
        fgets(key, sizeof(key), stdin);
        key[strcspn(key, "\n")] = '\0';

        encrypt(filename, message, key);
    }
    else if (choice == 'd') {
        char filename[100];
        char key[32];

        printf("Enter the filename: ");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\n")] = '\0';

        printf("Enter the decryption key: ");
        fgets(key, sizeof(key), stdin);
        key[strcspn(key, "\n")] = '\0';

        decrypt(filename, key);
    }
    else {
        printf("Invalid choice.\n");
    }

    return 0;
}