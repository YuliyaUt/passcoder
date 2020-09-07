import base64
import random
import binascii
import hashlib


program_private_key = 1
program_public_key = 1


def get_param_by_key(params, key, message):
    if (key in params) and (len(params) > (params.index(key) + 1)):
        ind = params.index(key)
        param = params[ind + 1]
    else:
        print(message)
        param = input()
    return param


# Counts Legendre symbol for i mod p
def legendre_symbol(i, p):
    return pow(i, (p-1) // 2, p)


# Returns minimal non-residue mod p - number a: a = x^2 (mod p) has no solutions mod p
def non_residue(p):
    for i in range(2, p-1):
        if legendre_symbol(i, p) == -1 % p:
            return i
    return 0


# Euclid's algorithm
def gcd(a, b):
    if a == 0 or b == 0:
        return 0
    if a < 0:
        a = - a
    if b < 0:
        b = - b
    # s = q * t + r
    s, t = max(a, b), min(a, b)
    r = s % t
    while r != 0:
        s, t = t, r
        r = s % t
    return t


# using Euclid's algorithm
def inverse(a, module):
    a = a % module
    if gcd(a, module) != 1:
        return 0
    n = 1
    s, t = module, a
    q, r = s // t, s % t
    p_prev, p = 0, 1
    while r != 0:
        p_prev, p = p, p * q + p_prev
        s, t = t, r
        q, r = s // t, s % t
        n += 1
    if n % 2 == 0:
        p *= -1
    return p


# Encodes strings in utf-8 to base32, then to number. If number too big for chosen system, return 0
def word_to_num(text, modulo):
    num = base32_to_num(base64.b32encode(text.encode("utf-8")))
    if num > modulo:
        return 0
    return num


# Encodes words in base32 to numbers in its own way
def base32_to_num(encoded_bytes):
    # 1. encode each symbol of base32 with i in [0, 31]
    # 2. add its code subsequently to bit representation of the number
    # 3. add padding+1 size which might be 1 to 8
    # NOTE: chosen order of symbols is: first alphabet, then 2-7
    num, i = 0, 0
    while i < len(encoded_bytes) and encoded_bytes[i] != ord('='):
        if ord('2') <= encoded_bytes[i] <= ord('7'):
            j = encoded_bytes[i] - ord('2') + 26
        else:
            j = encoded_bytes[i] - ord('A')
        num = num * 32 + j
        i += 1
    j = len(encoded_bytes) - i + 1
    num = num * 32 + j
    print("num = ", num)
    return num


# Decodes words in base 32 from numbers
def num_to_base32(num):
    # 1. retrieve padding size
    # 2. retrieve base32 symbol from its code subsequently (from bit representation of the number)
    # NOTE: chosen order of symbols is: first alphabet, then 2-7
    # on incorrect condition return ""
    if num == 0:
        return ""
    i = num
    padding, i = i % 32, i // 32
    bytes_list = []
    while i:
        rem, i = i % 32, i // 32
        if rem >= 26:
            bytes_list.append(chr(ord('2') + rem - 26))
        else:
            bytes_list.append(chr(ord('A') + rem))
    bytes_list.reverse()
    if not (1 <= padding <= 8):
        return ""
    for k in range(padding-1):
        bytes_list.append('=')
    print(bytes_list)
    word = "".join(bytes_list)
    return word


# Decodes strings in utf-8 from base32, which is retrieved fro, number. If cannot return ""
def num_to_word(num):
    s = num_to_base32(num)
    if not s:
        return ""
    try:
        word = base64.b32decode(s).decode("utf-8")
    except binascii.Error:
        return ""
    except UnicodeDecodeError:
        return ""
    return word


def square_root_by_prime_modulo(a, p):
    # 1. Represent p - 1 = (2 ** m) * s
    s = p - 1
    m = 0
    while s and s % 2 == 0:
        m = m + 1
        s = s // 2
    # 2. x = +- pow(B,j)*pow(a,(s+1)/2, p), B = pow(b,s,p), b is not full square
    b = non_residue(p)
    big_b = pow(b, s, p)
    # 3. if m=1, then j=0
    j = 0
    if m > 1:
        # 4. if m>1 A = a**s mod p
        big_a = pow(a, s, p)
        # 5. Make tables A[i] = A**(2**i)
        table_of_a = []
        table_of_b = []
        a_i = big_a
        b_i = big_b
        for i in range(m-1):
            table_of_a.append(a_i)
            table_of_b.append(b_i)
            a_i = pow(a_i, 2, p)
            b_i = pow(b_i, 2, p)
        table_of_j = []
        for t in range(m-1):
            eps_t = table_of_a[m-2-t]
            for y in range(t):
                y_t = table_of_b[m-2-t+1+y] ** table_of_j[y]
                eps_t = eps_t * y_t % p
            j_t = (1 - eps_t) % p // 2
            table_of_j.append(j_t)
            j = j + 2 ** t * j_t
    x = pow(big_b, j, p) * pow(a, (s+1)//2, p) % p
    return x


def verify_key(key, signature):
    return True


def extract_public_key(key_path):
    try:
        with open(key_path, 'r') as f:
            str_key = f.readline()
            str_sig = f.readline()
            # TODO: write checking of signature algorithm
            # TODO: write encryption algorithm
        key = int(str_key)
        signature = int(str_key)
        if verify_key(key, signature):
            return int(key)
        else:
            return 0
    except (OSError, IOError) as e:
        print("Could not read public key, caused by error({0}): {1}".format(e.errno, e.strerror))
    return 0


def extract_private_key(key_path):
    try:
        with open(key_path, 'rb') as f:
            b = f.readline()
            print("Please enter password to restore private key")
            passwd = input()
            p, q = eval(restore_private_key(b, passwd))
    except (SyntaxError, ValueError):
        print("Extracted private key is invalid! {0}")
        return 0, 0
    except (OSError, IOError) as e:
        print("Could not read private key: caused by error({0}): {1}".format(e.errno, e.strerror))
        return 0, 0
    return p, q


def encrypt_rabin(key_path, text):
    n = extract_public_key(key_path)
    if n == 0:
        print("Invalid key!")
        return ""
    m = word_to_num(text, n)
    if m == 0:
        print("Password is too big to encrypt with this cryptosystem! Try other params")
    c = pow(m, 2, n)
    ciphertext = base64.b32encode(str(c).encode("utf-8")).decode("utf-8")
    return ciphertext


def decrypt_rabin(key_path, ciphertext):
    p, q = extract_private_key(key_path)
    if not p or not q:
        return ""
    c = int(base64.b32decode(ciphertext.encode("utf-8")).decode("utf-8"))
    # print("c=", c)
    n = p * q
    # print("p,q,n=", p, q, n)
    c_p = c % p
    c_q = c % q
    m_p = square_root_by_prime_modulo(c_p, p)
    m_q = square_root_by_prime_modulo(c_q, q)
    m_1 = (m_p * q * inverse(q, p) + m_q * p * inverse(p, q)) % n
    m_2 = (m_p * q * inverse(q, p) - m_q * p * inverse(p, q)) % n
    m_3 = (- m_1) % n
    m_4 = (- m_2) % n
    # print(m_1, m_2, m_3, m_4)
    words = []
    words.append(num_to_word(m_1))
    words.append(num_to_word(m_2))
    words.append(num_to_word(m_3))
    words.append(num_to_word(m_4))
    # print(words)
    words.remove("")
    password = "".join(words)
    if not password:
        print("ERROR! Could not retrieve password from ciphertext")
    return password


def encryption_mode(params):
    print("Entering encryption mode...")
    key_path = get_param_by_key(params, "-k", "Enter path to file with previously registered public key:")
    password = get_param_by_key(params, "-p", "Enter the password to be encrypted:")
    print("Key path is", key_path)
    print("Password is", password)
    ciphertext = encrypt_rabin(key_path, password)
    if ciphertext:
        print("Ciphertext is", ciphertext)


def decryption_mode(params):
    print("Entering decryption mode...")
    key_path = get_param_by_key(params, "-k", "Enter path to file with previously registered private key:")
    ciphertext = get_param_by_key(params, "-c", "Enter the encrypted password in base32 encoding:")
    print("Key path is", key_path)
    print("Ciphertext is", ciphertext)
    password = decrypt_rabin(key_path, ciphertext)
    if password:
        print("Password is", password)


def get_random_prime(primes_filename, length):
    try:
        with open(primes_filename, 'r') as f:
            k = f.readline()
            before = 0
            while k and not len(k) == length + 1:
                k = f.readline()
                before += 1
            amount = 0
            while k and len(k) == length + 1:
                amount += 1
                k = f.readline()
            r = random.randint(0, amount)
        with open(primes_filename, 'r') as f:
            for i in range(before + r):
                f.readline()
            k = f.readline()
            if k:
                s = int(f.readline())
            else:
                s = 1
        return s
    except (OSError, IOError) as e:
        print("Could not get factor base, caused by error({0}): {1}".format(e.errno, e.strerror))


def get_hash(message):
    return 1


def signed(message):
    h = get_hash(message)
    return h ** program_private_key % program_public_key


def protect_private_key(private_key, passwd):
    m = hashlib.sha3_384()
    m.update(passwd.encode("utf-8"))
    b1 = m.digest()
    l1 = len(b1)
    str_private_key = str(private_key)
    if len(str_private_key) < l1:
        # padding
        str_private_key = str_private_key + "1";
        str_private_key = str_private_key + "0" * (l1-len(str_private_key));
    b2 = str_private_key.encode("utf-8")
    l2 = len(b2)
    assert l1 == l2
    arr_ans = bytearray(l1)
    for i in range(max(l1, l2)):
        arr_ans[i] = b1[i] ^ b2[i]
    ans = bytes(arr_ans)
    print(b1)
    print(b2)
    print(ans)
    return ans


def restore_private_key(hashed_private_key, passwd):
    m = hashlib.sha3_384()
    m.update(passwd.encode("utf-8"))
    b1 = m.digest()
    l1 = len(b1)
    b2 = hashed_private_key
    l2 = len(b2)
    if l1 != l2:
        return ""
    arr_private = bytearray(l1)
    for i in range(l1):
        arr_private[i] = b1[i] ^ b2[i]
    try:
        private = bytes(arr_private)
        private_key = private.decode("utf-8")
        k = 0
        for i in range(1, len(private)+1):
            if private_key[len(private_key)-i] == '1':
                k = len(private_key)-i
                break
        if k == 0:
            return ""
        private_key = private_key[0:k]
        return private_key
    except UnicodeDecodeError:
        return ""


def generate_rabin_keys(n):
    primes_filename = "primes — копия.txt"
    p = get_random_prime(primes_filename, n)
    q = get_random_prime(primes_filename, n)
    # print(p, q)
    private_key = p, q
    public_key = p * q
    print("Enter password to protect public and private keys")
    passwd = input()
    try:
        with open("user_public_key.txt", "w") as f:
            f.write(str(public_key) + "\n")
            f.write(str(signed(public_key)) + "\n")
            f.close()
        with open("user_private_key.txt", "wb") as f:
            f.write(protect_private_key(private_key, passwd))
            f.close()
    except (IOError, OSError):
        print("IO or OS Error, hence could not generate keys, quiting")
        return 0, (0, 0)
    return public_key, private_key


def registration_mode(params):
    print("Entering registration mode...")
    n = 9
    print("Key length is", n)
    generate_rabin_keys(n)
    print("Done! You can find your keys in files:")
    print("user_private_key.txt. user_public_key.txt")


def print_commands():
    print("-------------------------------------------------------------------")
    print("List of commands: \t\t| /help")
    print("Register in the system:\t| /register ")
    print("Encrypt the password: \t| /encrypt [-k pathToPublicKey] [-p password]")
    print("Decrypt the password: \t| /decrypt [-k pathToPrivateKey] [-c ciphertext]")
    print("Exit program: \t\t\t| /exit")
    print("-------------------------------------------------------------------")


def main():
    print("Welcome to passcoder! Here are the commands available:")
    # TODO add exceptions handling
    print_commands()
    while 1:
        command = input()
        if not command:
            continue
        if command == "/exit":
            print("Exiting...")
            break
        params = command.split(" ")
        option = params[0]
        if option == "/register":
            registration_mode(params)
        elif option == "/encrypt":
            encryption_mode(params)
        elif option == "/decrypt":
            decryption_mode(params)
        elif option == "/help":
            print_commands()
        else:
            print("Some unknown command. Try this:")
            print_commands()


if __name__ == "__main__":
    # generate_rabin_keys(9)
    # protect_private_key((633352309, 274292311), "mypasswd")
    # print(restore_private_key(protect_private_key((633352309, 274292311), "mypasswd"),"mypasswd"))
    # print(word_to_num("123456", 10000000000000000))
    # print(num_to_word(word_to_num("123456", 1000000000000000)))
    # /decrypt -k 1_user_private_key.txt -c GM4TIMRVHA2DC===
    # /decrypt -k 1_user_private_key.txt -c GY4TSNRTGQ3DCOBXGI3DE===
    # /decrypt -k 1_user_private_key.txt -c G4YDKMRQGA2TONZSHA2TS===
    # /decrypt -k 1_user_private_key.txt -c GUZTGNJZGI2DQMBZGI2TC===      2
    # /decrypt -k 1_user_private_key.txt -c GE4TKOBUGEYDMMJVGIZDMOI=
    # /decrypt -k user_private_key.txt -c GE2TOMJSGUYTANBSGQZDGNI=
    # /decrypt -k user_private_key.txt -c GIYTONZQGY2TOMJWGAYTCMI= 8
    # /decrypt -k user_private_key-protected.txt -c G44TGMZXGYYTQNRWGE2TENZWGU3A====
    # /encrypt -k user_public_key-protected.txt -p 124567
    # password is bullbullbull
    main()
