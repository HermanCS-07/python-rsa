import random
from math import floor
from math import sqrt

def banner():
    """
    Prints a cool 'RSA Encrypter/Decrypter' banner to the command line.
    """
    banner = """
    ██████╗  ███████╗ █████╗     ███████╗███╗   ██╗ ██████╗██╗   ██╗██████╗ ████████╗███████╗██████╗ ██╗   ██╗
    ██╔══██╗██╔════╝██╔══██╗     ██╔════╝████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗╚██╗ ██╔╝
    ██████╔╝███████╗███████║     █████╗  ██╔██╗ ██║██║      ╚████╔╝ ██████╔╝   ██║   █████╗  ██████╔╝ ╚████╔╝ 
    ██╔══██╗╚════██║██╔══██║     ██╔══╝  ██║╚██╗██║██║       ╚██╔╝  ██╔═══╝    ██║   ██╔══╝  ██╔══██╗  ╚██╔╝  
    ██║  ██║███████║██║  ██║     ███████╗██║ ╚████║╚██████╗   ██║   ██║        ██║   ███████╗██║  ██║   ██║   
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   
    -----------------------------------------------------------------------------------------------------
                      By RaSA Enak (Cryptography and Information Security, CSA Class)
    -----------------------------------------------------------------------------------------------------
    """
    print(banner)

# we want to generate prime numbers between 1000 - 1000000
rand_start = 1000
rand_end = 1000000 

# check if a number is prime using Rabin-Miller algorithm
def is_prime(n, k=40): # k is the number of iterations for accuracy
    """
    Tests if a number n is prime using the Rabin-Miller primality test.
    k is the number of rounds of testing to perform.
    Returns True if n is likely prime, False if it is composite.
    """
    if n < 2:
        return False
    if n == 2 or n == 3: # 2 and 3 are prime
        return True
    if n % 2 == 0: # even numbers other than 2 are not prime
        return False

    # write n-1 as 2^s * d, where d is odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # perform k iterations of the test
    for _ in range(k):
        a = random.randrange(2, n - 2) # pick a random base 'a' in [2, n-2]
        x = pow(a, d, n) # x = a^d mod n

        if x == 1 or x == n - 1:
            continue # n might be prime, try next iteration

        # repeat s-1 times: x = x^2 mod n
        # if x becomes n-1, n might be prime
        for _r in range(s - 1): # corrected loop variable to avoid conflict if 'r' was used outside
            x = pow(x, 2, n)
            if x == n - 1:
                break # n might be prime, break inner loop and go to next 'a'
        else:
            # if the inner loop completed and x is not n-1, then n is composite
            return False
            
    return True # n is likely prime after k iterations

# using Euclid's gcd algorithm! To verify whether e and phi(n) are coprime
# gcd(e, phi(n)) should be equal to 1
def gcd(a, b):

    if b == 0: # Added base case for Euclidean algorithm
        return a
    # Original logic was mostly fine, but this is a more standard iterative Euclidean algorithm
    while b:
        a, b = b, a % b
    return a

# using extended euclidean algorithm to calculate modular inverse of two numbers
# this is how we can the d value from e (modular inverse of e)
def modular_inverse(a, b):

    # Base case for recursive extended Euclidean algorithm
    if a == 0:
        # gcd(0, b) = b.  The equation is 0*x + b*y = b.  So x=0, y=1.
        return b, 0, 1 

    # Recursive call: modular_inverse(b % a, a)
    # This finds gcd(b % a, a) and coefficients x', y' such that (b % a)x' + ay' = gcd(b % a, a)
    gcd_val, x1_rec, y1_rec = modular_inverse(b % a, a)

    x_rec = y1_rec - (b // a) * x1_rec  # this is x for original 'a' (which is current 'b' in recursive call)
    y_rec = x1_rec                      # this is y for original 'b' (which is current 'a' in recursive call)
                                        # the roles of a and b are swapped in the recursive call's perspective
                                        # relative to the formula ax + by = gcd(a,b)

    return gcd_val, x_rec, y_rec


# we can also use the rabin miller algorithm to do so
def generate_large_prime(start=rand_start, end=rand_end):
    # generate a random number [rand_start, rand_end]
    num = random.randint(start, end)

    #check whether it is prime or not
    while not is_prime(num):
        num = random.randint(start, end)

    # return the prime number
    return num

def generate_rsa_keys(): 
    p = generate_large_prime()
    q = generate_large_prime()

    # Ensure p and q are different, though with large primes the chance is tiny
    while p == q:
        q = generate_large_prime()

    # trapdoor function, because p * q is fast
    # but trying to get p and q from n itself is extremely slow
    n =  p * q

    # euler's phi function
    phi = (p-1) * (q-1)

    # public key e
    e = random.randrange(1, phi)

    # making sure that the gcd of e and phi is 1
    g = gcd(e, phi) # Store gcd result
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi) # Recalculate gcd

    d_temp = modular_inverse(e, phi)[1] # _gcd_val should be 1
    
    # ensure d is positive and in the range [1, phi-1]
    d = d_temp % phi
    # if d_temp was negative, d_temp % phi might still be negative in Python if phi is positive.
    # a common way to ensure positive is (d_temp % phi + phi) % phi
    if d < 0: # d should be positive
        d += phi # ensures d is in [0, phi-1] if d_temp was negative 
    
    # return the private key and public key
    return (d, n), (e, n)


def rsa_encrypt(public_key, plaintext):

    # public key for encryption
    e, n = public_key

    # ciphertext will be a list of integers
    ciphertext_list = [] 

    # transform all chracters into integers and encrypt them with public key
    for char in plaintext: 
        a = ord(char)
        encrypted_char = pow(a, e, n) # same as a^e mod n
        ciphertext_list.append(encrypted_char) 

    return ciphertext_list


def rsa_decrypt(private_key, ciphertext_list): 

    # private key for decryption
    d, n = private_key

    plaintext_chars = [] # Corrected: Store decrypted characters in a list

    # ciphertext_list is a list of integers
    for c in ciphertext_list: 
        # 'a' was used for ord(p) in encrypt, here it's the decrypted ASCII value
        dec = pow(c, d, n) # same as c^d mod n
        try:
            plaintext_chars.append(chr(dec)) 
        except ValueError:
            # handle cases where decrypted_val might be out of chr() range,
            print(f"Warning: Decrypted value {decrypted_val} is not a valid character code.") # Restored original variable name
            plaintext_chars.append('?') # placeholder for non-decodable character   

    return "".join(plaintext_chars) 


if __name__ == '__main__':
    
    banner()

    private_key, public_key = generate_rsa_keys() 
    
    message = input("Input a message to be encrypted with RSA: ")

    print(f"Original message: {message}\n")
    print(f"Public key (e, n): {public_key}")
    print(f"Private key (d, n): {private_key}\n")

    cipher = rsa_encrypt(public_key, message) 
    ciphertext = ''

    print(f"Encrypted message: {cipher}")

    decrypted_message = rsa_decrypt(private_key, cipher)

    print(f"Decrypted message: {decrypted_message}")
    