#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Read an entire line, dynamically growing the buffer if necessary.
 *
 * The returned string is always null-terminated.
 * A trailing newline is removed.
 *
 * Returns:
 *   allocated string on success
 *   NULL on error/EOF
 */
char *readLine(const char *prompt)
{
    printf("%s", prompt);
    fflush(stdout); // this is new

    size_t capacity = 128; //size_t is also new, also everything is a size of 128 bytes now... that's weird
    size_t length = 0;

    char *buffer = malloc(capacity); //huh, malloc is being used, neat
    if (buffer == NULL) {
        return NULL;
    }

    int c;

    while ((c = getchar()) != EOF) { //I think EOF is also new but i know it means end of file
        /* Stop at newline. */
        if (c == '\n') {
            break;
        }

        /* Make room for character + '\0'. */
        if (length + 1 >= capacity) { //rolling reallocater to constantly expand the capacity size 
            capacity *= 2;

            char *temp = realloc(buffer, capacity); //realloc is also new
            if (temp == NULL) {
                free(buffer);
                return NULL;
            }

            buffer = temp;
        }

        buffer[length++] = (char)c;
    }

    /*
     * If EOF occurred before reading anything, treat it as
     * end-of-input rather than returning an empty string.
     */
    if (c == EOF && length == 0) {
        free(buffer);
        return NULL;
    }

    buffer[length] = '\0';

    return buffer;
}


/*
 * XOR data in-place.
 *
 * dataLen is used instead of looking for '\0', because encrypted
 * data can legitimately contain zero bytes.
 */
void xorEncryptDecrypt(
    unsigned char *data,
    size_t dataLen,
    const unsigned char *key,
    size_t keyLen)
{
    for (size_t i = 0; i < dataLen; i++) {
        data[i] ^= key[i % keyLen];
    }
}


/*
 * Encrypt a message and write the ciphertext to a file.
 */
int encrypt(
    const char *filename,
    const char *message,
    const char *key)
{
    size_t messageLen = strlen(message);
    size_t keyLen = strlen(key);

    if (keyLen == 0) {
        fprintf(stderr, "Error: encryption key cannot be empty.\n");
        return 0;
    }

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file for writing"); //also new but makes sense to throw an error instead of a print
        return 0;
    }

    /*
     * Make a writable copy because the original message is const.
     */
    unsigned char *data = malloc(messageLen); //more malloc

    if (messageLen > 0 && data == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(file);
        return 0;
    }

    memcpy(data, message, messageLen);

    xorEncryptDecrypt(
        data,
        messageLen,
        (const unsigned char *)key,
        keyLen
    );

    /*
     * IMPORTANT:
     * Use messageLen, not strlen(data).
     *
     * data is encrypted binary data and may contain '\0'.
     */
    size_t written = fwrite(data, 1, messageLen, file); 

    free(data);
    fclose(file);

    if (written != messageLen) {
        fprintf(stderr, "Error writing encrypted data.\n");
        return 0;
    }

    return 1;
}


/*
 * Decrypt a file.
 *
 * The file is treated as binary data, so '\0' bytes are allowed.
 */
int decrypt(
    const char *filename,
    const char *key)
{
    size_t keyLen = strlen(key);

    if (keyLen == 0) {
        fprintf(stderr, "Error: decryption key cannot be empty.\n");
        return 0;
    }

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file for reading");
        return 0;
    }

    /*
     * Determine file size.
     */
    if (fseek(file, 0, SEEK_END) != 0) { //fseek is new
        fprintf(stderr, "Error seeking file.\n");
        fclose(file);
        return 0;
    }

    long fileSize = ftell(file); //ftell is new

    if (fileSize < 0) {
        fprintf(stderr, "Error determining file size.\n");
        fclose(file);
        return 0;
    }

    if (fseek(file, 0, SEEK_SET) != 0) { //more fseek
        fprintf(stderr, "Error seeking file.\n");
        fclose(file);
        return 0;
    }

    size_t dataLen = (size_t)fileSize;

    unsigned char *data = malloc(dataLen + 1); //more malloc

    if (dataLen > 0 && data == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(file);
        return 0;
    }

    size_t bytesRead = fread(data, 1, dataLen, file);

    fclose(file);

    if (bytesRead != dataLen) {
        fprintf(stderr, "Error reading file.\n");
        free(data);
        return 0;
    }

    xorEncryptDecrypt(
        data,
        dataLen,
        (const unsigned char *)key,
        keyLen
    );

    /*
     * The original plaintext is assumed to be text.
     * Print exactly dataLen bytes rather than stopping at '\0'.
     */
    fwrite(data, 1, dataLen, stdout);
    putchar('\n');

    free(data);

    return 1;
}


int main(void)
{
    char *choice = readLine(
        "Do you want to encrypt or decrypt? (e/d): "
    );

    if (choice == NULL) {
        fprintf(stderr, "Error reading choice.\n");
        return EXIT_FAILURE; //also new
    }

    if (choice[0] == 'e' && choice[1] == '\0') {

        char *filename = readLine("Enter the filename: ");
        if (filename == NULL) {
            fprintf(stderr, "Error reading filename.\n");
            free(choice);
            return EXIT_FAILURE;
        }

        char *message = readLine("Enter the message to encrypt: ");
        if (message == NULL) {
            fprintf(stderr, "Error reading message.\n");
            free(filename);
            free(choice);
            return EXIT_FAILURE;
        }

        char *key = readLine("Enter the encryption key: ");
        if (key == NULL) {
            fprintf(stderr, "Error reading key.\n");
            free(message);
            free(filename);
            free(choice);
            return EXIT_FAILURE;
        }

        encrypt(filename, message, key);

        free(key);
        free(message);
        free(filename);
    }
    else if (choice[0] == 'd' && choice[1] == '\0') {

        char *filename = readLine("Enter the filename: ");
        if (filename == NULL) {
            fprintf(stderr, "Error reading filename.\n");
            free(choice);
            return EXIT_FAILURE;
        }

        char *key = readLine("Enter the decryption key: ");
        if (key == NULL) {
            fprintf(stderr, "Error reading key.\n");
            free(filename);
            free(choice);
            return EXIT_FAILURE;
        }

        decrypt(filename, key);

        free(key);
        free(filename);
    }
    else {
        printf("Invalid choice.\n");
    }

    free(choice);

    return EXIT_SUCCESS;
}
