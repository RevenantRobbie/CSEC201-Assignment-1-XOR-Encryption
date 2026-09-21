#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/*
 * Read one line of input dynamically.
 *
 * The returned buffer is null-terminated for convenience, but
 * its actual length is returned separately.
 *
 * A trailing newline is removed. EOF without a newline is valid.
 */
static char *read_line(const char *prompt, size_t *length)
{
    size_t capacity = 128;
    size_t used = 0;

    char *buffer = malloc(capacity);

    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    printf("%s", prompt);
    fflush(stdout);

    int ch;

    while ((ch = getchar()) != EOF && ch != '\n') {
        if (used == capacity - 1) {
            if (capacity > (size_t)-1 / 2) {
                fprintf(stderr, "Input is too large.\n");
                free(buffer);
                return NULL;
            }

            size_t new_capacity = capacity * 2;
            char *temp = realloc(buffer, new_capacity);

            if (temp == NULL) {
                fprintf(stderr, "Memory allocation failed.\n");
                free(buffer);
                return NULL;
            }

            buffer = temp;
            capacity = new_capacity;
        }

        buffer[used++] = (char)ch;
    }

    if (ch == EOF && used == 0) {
        free(buffer);
        return NULL;
    }

    buffer[used] = '\0';
    *length = used;

    return buffer;
}

/*
 * Apply repeating-key XOR to a byte buffer.
 *
 * XOR is symmetric, so this function is used for both
 * encryption and decryption.
 *
 * The data and key are length-based byte sequences.
 * Neither needs to contain a terminating null byte.
 */
static int xor_transform(
    unsigned char *data,
    size_t data_length,
    const unsigned char *key,
    size_t key_length)
{
    if (key_length == 0) {
        fprintf(stderr, "The encryption key cannot be empty.\n");
        return 0;
    }

    for (size_t i = 0; i < data_length; ++i) {
        data[i] ^= key[i % key_length];
    }

    return 1;
}

/* Encrypt a message and write its bytes to a file. */
static int encrypt_file(
    const char *filename,
    const unsigned char *message,
    size_t message_length,
    const unsigned char *key,
    size_t key_length)
{
    if (key_length == 0) {
        fprintf(stderr, "The encryption key cannot be empty.\n");
        return 0;
    }

    unsigned char *data = NULL;

    if (message_length > 0) {
        data = malloc(message_length);

        if (data == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            return 0;
        }

        memcpy(data, message, message_length);
    }

    if (!xor_transform(data, message_length, key, key_length)) {
        free(data);
        return 0;
    }

    FILE *file = fopen(filename, "wb");

    if (file == NULL) {
        perror("Error opening file for writing");
        free(data);
        return 0;
    }

    size_t written = 0;

    if (message_length > 0) {
        written = fwrite(data, 1, message_length, file);
    }

    int success = (written == message_length);

    if (fclose(file) != 0) {
        perror("Error closing file");
        success = 0;
    }

    if (!success) {
        fprintf(stderr, "Error writing encrypted data.\n");
    }

    free(data);
    return success;
}

/* Read an entire file, decrypt its bytes, and write them to stdout. */
static int decrypt_file(
    const char *filename,
    const unsigned char *key,
    size_t key_length)
{
    if (key_length == 0) {
        fprintf(stderr, "The decryption key cannot be empty.\n");
        return 0;
    }

    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        perror("Error opening file for reading");
        return 0;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("Error seeking file");
        fclose(file);
        return 0;
    }

    long file_size = ftell(file);

    if (file_size < 0) {
        perror("Error determining file size");
        fclose(file);
        return 0;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        perror("Error seeking file");
        fclose(file);
        return 0;
    }

    size_t length = (size_t)file_size;

    if ((long)length != file_size) {
        fprintf(stderr, "File is too large to process.\n");
        fclose(file);
        return 0;
    }

    unsigned char *data = NULL;

    if (length > 0) {
        data = malloc(length);

        if (data == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            fclose(file);
            return 0;
        }

        size_t bytes_read = fread(data, 1, length, file);

        if (bytes_read != length) {
            fprintf(stderr, "Error reading encrypted data.\n");
            free(data);
            fclose(file);
            return 0;
        }
    }

    if (fclose(file) != 0) {
        perror("Error closing file");
        free(data);
        return 0;
    }

    if (!xor_transform(data, length, key, key_length)) {
        free(data);
        return 0;
    }

    /* Use fwrite, not printf("%s"), because plaintext may contain NUL. */
    if (length > 0 && fwrite(data, 1, length, stdout) != length) {
        fprintf(stderr, "Error writing decrypted data.\n");
        free(data);
        return 0;
    }

    free(data);
    return 1;
}

int main(void)
{
    size_t choice_length;
    char *choice = read_line(
        "Do you want to encrypt or decrypt? (e/d): ",
        &choice_length
    );

    if (choice == NULL) {
        fprintf(stderr, "No choice provided.\n");
        return EXIT_FAILURE;
    }

    if (choice_length != 1 ||
        (choice[0] != 'e' && choice[0] != 'd')) {
        fprintf(stderr, "Invalid choice.\n");
        free(choice);
        return EXIT_FAILURE;
    }

    int encrypting = (choice[0] == 'e');
    free(choice);

    size_t filename_length;
    char *filename = read_line("Enter the filename: ", &filename_length);

    if (filename == NULL || filename_length == 0) {
        fprintf(stderr, "Invalid filename.\n");
        free(filename);
        return EXIT_FAILURE;
    }

    size_t key_length;
    char *key = read_line(
        encrypting ? "Enter the encryption key: "
                  : "Enter the decryption key: ",
        &key_length
    );

    if (key == NULL || key_length == 0) {
        fprintf(stderr, "The encryption key cannot be empty.\n");
        free(filename);
        free(key);
        return EXIT_FAILURE;
    }

    int success;

    if (encrypting) {
        size_t message_length;
        char *message = read_line(
            "Enter the message to encrypt: ",
            &message_length
        );

        if (message == NULL) {
            fprintf(stderr, "No message provided.\n");
            free(filename);
            free(key);
            return EXIT_FAILURE;
        }

        success = encrypt_file(
            filename,
            (const unsigned char *)message,
            message_length,
            (const unsigned char *)key,
            key_length
        );

        free(message);
    } else {
        success = decrypt_file(
            filename,
            (const unsigned char *)key,
            key_length
        );

        if (success) {
            putchar('\n');
        }
    }

    free(filename);
    free(key);

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}