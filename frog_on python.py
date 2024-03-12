MIN_BLOCK_SIZE = 8  # Минимальный размер блока [байты] = 64 бита
MAX_BLOCK_SIZE = 128  # Максимальный размер блока [байты] = 1024 бита
MIN_KEY_SIZE = 5  # Минимальный размер ключа [байты] = 40 бит
MAX_KEY_SIZE = 125  # Максимальный размер ключа [байты] = 1000 бит
DIR_ENCRYPT = 0  # Маркер для шифрования
DIR_DECRYPT = 1  # Маркер для дешифрования

numIter = 8  # Количество итераций в основном цикле
maxInternalKeySize = numIter * (2 * 16 + 256)


def makePermutation(permutation, lastElem):
    use = list(range(lastElem + 1))
    last = lastElem
    j = 0
    for i in range(lastElem):
        j = (j + permutation[i]) % (last + 1)
        permutation[i] = use[j]
        if j < last:
            use[j:last] = use[j + 1:last + 1]  # Эмулирует поведение move в Pascal
        last -= 1
        if j > last:
            j = 0
    permutation[lastElem] = use[0]
    return permutation


def invertPermutation(permutation, lastElem):
    # invert = [0] * (lastElem + 1)
    # for i in range(lastElem + 1):
    #     invert[permutation[i]] = i
    # # Обновляем исходную перестановку инвертированной
    # for i in range(lastElem + 1):
    #     permutation[i] = invert[i]
    inverted_permu = [-1] * len(permutation)
    for i, val in enumerate(permutation):
        if inverted_permu[val] != -1:
            raise ValueError("Invalid permutation, multiple values point to the same index.")
        inverted_permu[val] = i

    return inverted_permu


def makeInternalKey(direction, internalKey, blockSize):
    # Преобразует внутренний ключ с произвольными значениями в структурированный, валидный внутренний ключ
    internKey = bytearray(internalKey)
    used = [False] * MAX_BLOCK_SIZE
    top_key = bytearray(internalKey)
    ikPosi = 0
    for ite in range(numIter):
        # print(f"xoru: {top_key[ikPosi:ikPosi + 16]}")
        # print(f"permu: {top_key[ikPosi+16:ikPosi + 272]}")
        # print(f"bomb: {top_key[ikPosi+272:ikPosi + 288]}")
        ikPosi += blockSize
        permu = makePermutation(internKey[ikPosi:ikPosi+256], 255)
        if direction == DIR_DECRYPT:
            # print(F"???? {permu}")
            permu = invertPermutation(permu, 255)
            # print(F"???? {permu}")
        
        top_key[ikPosi:ikPosi + 256] = permu 
        # print(f"xoru: {top_key[0:ikPosi]}")
        # print(f"permu: {top_key[ikPosi:ikPosi + 256]}")
        # print(top_key)
        ikPosi += 256
        bombPermu = internKey[ikPosi:ikPosi+16]
        bombPermu = makePermutation(bombPermu, blockSize - 1)

        # Убедимся, что bombPermu имеет максимальный цикл размером BLOCK_SIZE
        used = [False] * blockSize
        j = 0
        for i in range(blockSize - 1):
            if bombPermu[j] == 0:
                # print(f"bombPermy[{j}] = {bombPermu}")
                k = j
                while used[k]:
                    k = (k + 1) % blockSize
                bombPermu[j] = k
                l = k
                count = 0
                while bombPermu[l] != k:
                    l = bombPermu[l]
                    # count += 1
                    # if count > 300:
                    #     k = bombPermu[l]
                bombPermu[l] = 0
            used[j] = True
            j = bombPermu[j]

        # Убедимся, что Bomb permutation никогда не указывает на следующий элемент
        for i in range(blockSize):
            if bombPermu[i] == (i + 1) % blockSize:
                bombPermu[i] = (i + 2) % blockSize
        top_key[ikPosi:ikPosi + 16] = bombPermu
        # print(f"bomb: {top_key[ikPosi:ikPosi + 16]}")
        ikPosi += blockSize

    return top_key


# def encrypt_frog_for_key(plain_text, internal_key, cipher_text, block_size):
#     """
#     Использует internalKey для шифрования plainText размером blockSize байт
#     и оставляет результат в cipherText; plainText и cipherText могут указывать
#     на одну и ту же позицию.
#     """
#     cipher_te = cipher_text
#     intern_key = internal_key
#     ik_posi = 0
#     # Копируем plainText в cipherText
#     cipher_te[:block_size] = plain_text[:block_size]
#     for ite in range(numIter - 1):
#         xor_bu = intern_key[ik_posi:ik_posi + block_size]
#         ik_posi += block_size
#         subst_permu = intern_key[ik_posi:ik_posi + 256]
#         ik_posi += 256
#         bomb_permu = intern_key[ik_posi:ik_posi + block_size]
#         ik_posi += block_size
#         for ib in range(block_size - 1):
#             cipher_te[ib] ^= xor_bu[ib]
#             cipher_te[ib] = subst_permu[cipher_te[ib]]
#             if ib < block_size - 1:
#                 cipher_te[ib + 1] ^= cipher_te[ib]
#             else:
#                 cipher_te[0] ^= cipher_te[ib]
#             cipher_te[bomb_permu[ib]] ^= cipher_te[ib]
#     return cipher_te


def encrypt_frog(plain_text, internal_key, cipher_text, block_size):
    """
    Использует internalKey для шифрования plainText размером blockSize байт
    и оставляет результат в cipherText; plainText и cipherText могут указывать
    на одну и ту же позицию.
    """
    cipher_te = bytearray(cipher_text)
    intern_key = bytearray(internal_key)
    ik_posi = 0
    # Копируем plainText в cipherText
    cipher_te[:block_size] = bytearray(plain_text[:block_size])
    for ite in range(numIter - 1):
        xor_bu = intern_key[ik_posi:ik_posi + block_size]
        ik_posi += block_size
        subst_permu = intern_key[ik_posi:ik_posi + 256]
        ik_posi += 256
        bomb_permu = intern_key[ik_posi:ik_posi + block_size]
        ik_posi += block_size
        for ib in range(block_size-1):
            cipher_te[ib] ^= xor_bu[ib]
            cipher_te[ib] = subst_permu[cipher_te[ib]]
            if ib < block_size - 1:
                cipher_te[ib + 1] ^= cipher_te[ib]
            else:
                cipher_te[0] ^= cipher_te[ib]
            # print(f"!!!!!!!!!!!!!!!!!!!!!!! = {bomb_permu[ib]}")
            cipher_te[bomb_permu[ib]] ^= cipher_te[ib]
    return cipher_te


def decrypt_frog(cipher_text, internal_key, plain_text, block_size):
    """
    Использует internalKey для дешифрования cipherText размером blockSize байт
    и оставляет результат в plainText; cipherText и plainText могут указывать
    на одну и ту же позицию.
    """
    plain_te = bytearray(plain_text)
    intern_key = bytearray(internal_key)
    ik_posi = 8 * (2 * block_size + 256)  # Размер внутреннего ключа
    # Копируем cipherText в plainText
    plain_te[:block_size] = bytearray(cipher_text[:block_size])
    for ite in range(numIter - 1, -1, -1):
        ik_posi -= block_size
        bomb_permu = intern_key[ik_posi:ik_posi + block_size]
        ik_posi -= 256
        subst_permu = intern_key[ik_posi:ik_posi + 256]
        ik_posi -= block_size
        xor_bu = intern_key[ik_posi:ik_posi + block_size]
        for ib in range(block_size - 1, -1, -1):
            plain_te[bomb_permu[ib]] ^= plain_te[ib]
            if ib < block_size - 1:
                plain_te[ib + 1] ^= plain_te[ib]
            else:
                plain_te[0] ^= plain_te[block_size - 1]
            plain_te[ib] = subst_permu[plain_te[ib]]
            plain_te[ib] ^= xor_bu[ib]
    return plain_te

# def replicate_key(original_key, required_length):
#     repetitions = required_length // len(original_key)
#     remainder = required_length % len(original_key)
#     replicated_key = original_key * repetitions
#     if remainder > 0:
#         replicated_key += original_key[:remainder]
#     return replicated_key

# def replicate_master_key(master_key, required_length):
#     repetitions = required_length // len(master_key)
#     remainder = required_length % len(master_key)
#     replicated_master_key = master_key * repetitions
#     if remainder > 0:
#         replicated_master_key += master_key[:remainder]
#     return replicated_master_key


def hashKey(binaryKey, keyLen, blockSize, randomKey, direction):
    # Использует binaryKey для заполнения randomKey значениями
    # с хорошими статистическими свойствами
    randomSeed = [
        # список значений для начального состояния генератора случайных чисел
    
        113, 21, 232, 18, 113, 92, 63, 157, 124, 193, 166, 197, 126, 56, 229, 229,
        156, 162, 54, 17, 230, 89, 189, 87, 169, 0, 81, 204, 8, 70, 203, 225,
        160, 59, 167, 189, 100, 157, 84, 11, 7, 130, 29, 51, 32, 45, 135, 237,
        139, 33, 17, 221, 24, 50, 89, 74, 21, 205, 191, 242, 84, 53, 3, 230,
        231, 118, 15, 15, 107, 4, 21, 34, 3, 156, 57, 66, 93, 255, 191, 3,
        85, 135, 205, 200, 185, 204, 52, 37, 35, 24, 68, 185, 201, 10, 224, 234,
        7, 120, 201, 115, 216, 103, 57, 255, 93, 110, 42, 249, 68, 14, 29, 55,
        128, 84, 37, 152, 221, 137, 39, 11, 252, 50, 144, 35, 178, 190, 43, 162,
        103, 249, 109, 8, 235, 33, 158, 111, 252, 205, 169, 54, 10, 20, 221, 201,
        178, 224, 89, 184, 182, 65, 201, 10, 60, 6, 191, 174, 79, 98, 26, 160,
        252, 51, 63, 79, 6, 102, 123, 173, 49, 3, 110, 233, 90, 158, 228, 210,
        209, 237, 30, 95, 28, 179, 204, 220, 72, 163, 77, 166, 192, 98, 165, 25,
        145, 162, 91, 212, 41, 230, 110, 6, 107, 187, 127, 38, 82, 98, 30, 67,
        225, 80, 208, 134, 60, 250, 153, 87, 148, 60, 66, 165, 72, 29, 165, 82,
        211, 207, 0, 177, 206, 13, 6, 14, 92, 248, 60, 201, 132, 95, 35, 215,
        118, 177, 121, 180, 27, 83, 131, 26, 39, 46, 12
    ]
    simpleKey = bytearray([0] * maxInternalKeySize)
    # simpleKey = replicate_key(binaryKey, maxInternalKeySize)
    # randomSeed = replicate_master_key(randomSeed, maxInternalKeySize)
    # print(simpleKey)
    iSeed = 0
    iKey = 0
    keyLen1 = keyLen - 1
    i = 0
    for i in range(maxInternalKeySize - 1):
        simpleKey[i] = randomSeed[iSeed] ^ binaryKey[iKey]
        iSeed = (iSeed + 1) % 251
        iKey = (iKey + 1) % keyLen
    simpleKey = makeInternalKey(DIR_ENCRYPT, simpleKey, blockSize)
    buffer = bytearray([0] * blockSize)
    last = min(keyLen1, blockSize - 1)
    for i in range(last+1):
        buffer[i] ^= binaryKey[i]
    buffer[0] ^= keyLen
    i = 0
    while i < maxInternalKeySize:
        buffer = encrypt_frog(buffer, simpleKey, buffer, blockSize)
        size = maxInternalKeySize - i
        size = min(size, blockSize)
        randomKey[i:i + size] = buffer[:size]
        i += size
    return randomKey


def make_key(key, direction, key_len, key_material, block_size):
    """
    Вычисляет внутренний ключ.
    Входные данные:
        Направление шифрования (DIR_ENCRYPT или DIR_DECRYPT).
        Ключевой материал, бинарный массив, который содержит ключ пользователя.
        KeyLen, длина бинарного ключа в байтах. (Например, для ключа длиной 128
            бит, keyLen = 16.) 
        BlockSize, размер блоков, которые будут шифроваться или дешифроваться.
    Возвращает:
        экземпляр ключа, содержащий внутренний ключ.
    """
    randomKey = bytearray(maxInternalKeySize)
    internalKey = hashKey(key_material, key_len, block_size, randomKey, direction)
    keyReady = makeInternalKey(direction, internalKey, block_size)
    return keyReady


def main():
    # blockSize = int(input("Введите размер блока (в байтах): "))
    # keyLen = int(input("Введите размер ключа (в байтах): "))
    # binaryKey = bytearray(input("Введите двоичный ключ: "), 'utf-8')
    blockSize = 16
    keyLen = 16
    # binaryKey = bytearray('mysecretpassword', 'utf-8')
    # # Шифрование
    # plaintext = bytearray(input("Введите текст для шифрования: "), 'utf-8')
    binaryKey = "0000000000000000".encode('ISO-8859-1')
    plaintext = "hellohellohelloh".encode('ISO-8859-1')
    key_to_encrypt = make_key(binaryKey, 0, keyLen, binaryKey, blockSize)
    print(f"key_to_encrypt = {key_to_encrypt}")
    ciphertext = encrypt_frog(plaintext, key_to_encrypt, plaintext, blockSize)
    print("Зашифрованный текст:", ciphertext)

    # Дешифрование
    key_to_dencrypt = make_key(binaryKey, 1, keyLen, binaryKey, blockSize)
    print(f"key_to_dencrypt = {key_to_dencrypt}")
    decrypted_text = decrypt_frog(ciphertext, key_to_dencrypt, ciphertext, blockSize)
    a=len(decrypted_text)
    print("Дешифрованный текст: ", decrypted_text.decode('ISO-8859-1'))
    count = 0
    print('\n\n\n\n\n\n\n\n\n\n\n')
    for i in range(8):

        print(f"Первая часть энкрипт: {key_to_encrypt[count:count+16]}")
        print(f"Первая часть дэкрипт: {key_to_dencrypt[count:count+16]}")
        print("------------------------------------------------------------------------------------")
        print(f"Вторая часть энкрипт: {key_to_encrypt[count+16:count+272]}")
        print(f"Вторая часть дэкрипт: {key_to_dencrypt[count+16:count+272]}")
        print("------------------------------------------------------------------------------------")
        print(f"Третья часть энкрипт: {key_to_encrypt[count+272:count+288]}")
        print(f"Третья часть дэкрипт: {key_to_dencrypt[count+272:count+288]}")
        print("------------------------------------------------------------------------------------")
        count+=288


if __name__ == "__main__":
    main()