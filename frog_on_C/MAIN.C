/*

FILENAME:  main.c

AES Submission: FROG

Principal Submitter: TecApro

*/

#include "frog.h"
#include "tests.h"
#include <string.h> 
#include <locale.h>
#include <stdio.h>
// Функция для преобразования текста в шестнадцатеричную строку
void textToHexString(const char *text, char *hexString) {
    while (*text) {
        sprintf(hexString, "%02x", (unsigned char)*text); // Преобразование символа в шестнадцатеричное
        hexString += 2;
        text++;
    }
    *hexString = '\0'; 
}
// Функция для преобразования шестнадцатеричной строки в текст
void hexStringToText(const char *hexString, char *text) {
    char *textPtr = text;
    while (*hexString && *(hexString+1)) {
        unsigned int value;
        sscanf(hexString, "%02x", &value);
        *textPtr++ = (char)value;
        hexString += 2;
    }
    *textPtr = '\0'; 
}

int main() {
    setlocale(LC_ALL, "Rus");
    char originalText[] = "Etomy kody 26let";
    char hexText[256];
    textToHexString(originalText, hexText);
    
    const char *keyMaterial = "000102030405060708090a0b0c0d0e0f";
    char IV[MAX_IV_SIZE*2 + 1] = "00000000000000000000000000000000";
    BYTE encrypted[BLOCK_SIZE], decrypted[BLOCK_SIZE];
    keyInstance keyInst;
    cipherInstance cipher;

    // Инициализация ключа и шифра
    if (makeKey(&keyInst, DIR_ENCRYPT, strlen(keyMaterial) * 4, (char *)keyMaterial) != TRUE) {
        printf("Ошибка при создании ключа.\n");
        return 1;
    }

    if (cipherInit(&cipher, MODE_ECB, IV) != TRUE) {
        printf("Ошибка при инициализации шифра.\n");
        return 1;
    }

    BYTE input[BLOCK_SIZE];
	// Преобразование шестнадцатеричной строки в двоичный формат
    hexStringToBinary(hexText, input, BLOCK_SIZE);

    // Шифрование
    if (blockEncrypt(&cipher, &keyInst, input, BLOCK_SIZE * 8, encrypted) != TRUE) {
        printf("Ошибка при шифровании.\n");
        return 1;
    }

    // Изменяем направление для ключа на расшифровку
    makeKey(&keyInst, DIR_DECRYPT, strlen(keyMaterial) * 4, (char *)keyMaterial);

    // Расшифровка
    if (blockDecrypt(&cipher, &keyInst, encrypted, BLOCK_SIZE * 8, decrypted) != TRUE) {
        printf("Ошибка при расшифровке.\n");
        return 1;
    }

    // Вывод результатов
    char encryptedHex[BLOCK_SIZE * 2 + 1], decryptedHex[BLOCK_SIZE * 2 + 1], decryptedText[128];
    binaryToHexString(encrypted, encryptedHex, BLOCK_SIZE);
    binaryToHexString(decrypted, decryptedHex, BLOCK_SIZE);
    hexStringToText(decryptedHex, decryptedText); // Преобразование обратно в текст
    
    printf("Encrypted text: %s\n", encryptedHex);
    printf("Decrypted hex: %s\n", decryptedHex);
    printf("Decrypted text: %s\n", decryptedText);

    return 0;
}