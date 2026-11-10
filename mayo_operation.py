
#  implementation en python des operation dans le corps f16 

# additon 
def add(a, b):
    return a ^ b


# soustraction
def subtract(a, b):
    return a ^ b


# multiplication 
# polynome irreductible : X^4 + X + 1
def multiply(a, b):
    result = 0

    while b:
        if b & 1:
            result ^= a

        a <<= 1

        if a & 0b10000:
            a ^= 0b10011

        b >>= 1

    return result


# puissance
def power(a, exponent):
    result = 1

    while exponent > 0:
        if exponent & 1:
            result = multiply(result, a)

        a = multiply(a, a)
        exponent >>= 1

    return result


# inverse 
def inverse(a):
    if a == 0:
        raise ValueError("Zero n'a pas d'inverse")

    return power(a, 14)


# division  
def divide(a, b):
    if b == 0:
        raise ValueError("Division par zero")

    return multiply(a, inverse(b))


# def test_f16():

#     print("===== TESTS DU CORPS F16 =====")

#     print("7 + 5 =", add(7, 5))
#     print("7 * 5 =", multiply(7, 5))
#     print("2 puissance 3 =", power(2, 3))
#     print("Inverse de 7 =", inverse(7))
#     print("7 / 5 =", divide(7, 5))

#     # Verification de tous les inverses
#     for a in range(1, 16):
#         assert multiply(a, inverse(a)) == 1

#     print("\nTous les tests sont reussis !")


# if __name__ == "__main__":
#     test_f16()

