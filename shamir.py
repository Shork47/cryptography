import random
from math import gcd

def Eratosfen(n):
    """Функция для нахождения всех простых чисел до n с помощью решета Эратосфена."""
    prime = [True for i in range(n+1)]
    p = 2
    while (p * p <= n):
        if (prime[p] == True):
            for i in range(p * p, n+1, p):
                prime[i] = False
        p += 1
    prime_numbers = [p for p in range(2, n) if prime[p]]
    return prime_numbers

def NOD(e, b):
    '''Нахождение e с учетом наибольшего общего делителя, то есть НОД(e, p - 1) = 1'''
    while gcd(e, b) != 1:
        e = random.randint(1, b)
    return e

def Count_d(e, p):
    '''Посчет d по формуле с учетом того, что (d * e) mod (p - 1) = 1'''
    d = 0
    while (d * e) % (p) != 1:
        d = random.randint(1, p)
    return d

def Encrypt(m, p, name):
    '''Ширование по формуле (m ^ e) mod p'''
    e = NOD(0, p - 1)
    print(f"e {name} = {e}")
    encrypted_text = [(char ** e) % p for char in m]
    return encrypted_text, e

def Decrypt(encrypted_text, p, e, name):
    '''Расшифрование по формуле (m ^ d) mod p'''
    d = Count_d(e, p - 1)
    print(f"d {name} = {d}")
    decrypted_text = [(char ** d) % p for char in encrypted_text]
    return decrypted_text

def string_to_numbers(s):
    ''' Возвращает целочисленное представление его Unicode кода '''
    return [ord(char) for char in s]

def numbers_to_string(n):
    '''Воздращает обратно из unicode символы'''
    return ''.join(chr(char) for char in n)

prime_numbers = Eratosfen(2**20)

p = random.choice(prime_numbers[100:])
print(f"Выбранное простое число p = {p}")

# Ввод строки вместо числа
m = input("Введите сообщение: ")
numbers = string_to_numbers(m)
message_A, e_Alice = Encrypt(numbers, p, "Алисы")
message_AB, e_Bob = Encrypt(message_A, p, "Боба")
message_B = Decrypt(message_AB, p, e_Alice, "Алисы")
message = Decrypt(message_B, p, e_Bob, "Боба")

final_message = numbers_to_string(message)
print(f"Итоговое сообщение: {final_message}")
