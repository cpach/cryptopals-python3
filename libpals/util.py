#!/usr/bin/env python3

from Crypto.Cipher import AES
from operator import itemgetter
from itertools import combinations

character_frequency = {
    'e': 27,
    't': 26,
    'a': 25,
    'o': 24,
    'i': 23,
    'n': 22,
    's': 21,
    'r': 20,
    'h': 19,
    'l': 18,
    'd': 17,
    'c': 16,
    'u': 15,
    'm': 14,
    'f': 13,
    'p': 12,
    'g': 11,
    'w': 10,
    'y': 9,
    'b': 8,
    'v': 7,
    'k': 6,
    'x': 5,
    ' ': 4,
    'j': 3,
    'q': 2,
    'z': 1
}


def xor_singlechar(input_bytes, key_value):
    output = b''

    for char in input_bytes:
        output += bytes([char ^ key_value])

    return output


def xor_find_singlechar_key(ciphertext):
    candidates = list()

    for key_candidate in range(256):
        total_score = 0
        plaintext_candidate = xor_singlechar(ciphertext, key_candidate)

        for byte in plaintext_candidate:
            char_score = character_frequency.get(chr(byte), 0)
            total_score += char_score

        # We might as well include the plaintext in the output since
        # it’s used in some of the challenges.
        result = {
            'key': key_candidate,
            'score': total_score,
            'plaintext': plaintext_candidate
        }

        candidates.append(result)

    winner = max(candidates, key=itemgetter('score'))

    return winner


def popcount(x):
    """Return the number of set bits in an integer (a.k.a the Hamming weight).
    """

    return bin(x).count('1')


def hamming_distance(a, b):
    """Take two bytes objects and return the number of differing bits
    (a.k.a. the Hamming distance).
    """

    total_score = 0

    for (byte_a, byte_b) in zip(a, b):
        current_score = popcount(byte_a ^ byte_b)
        total_score += current_score

    return total_score


def extend_buffer(buffer, length):
    """Take a string or bytes object and repeat for "length" characters.
    """
    return (buffer*length)[:length]


def fixed_xor(first_buffer, second_buffer):
    if (len(first_buffer) != len(second_buffer)):
        raise ValueError('Both arguments need to have the same length')

    output = b''

    for x, y in zip(first_buffer, second_buffer):
        output += bytes([x ^ y])

    return output


def xor_repeatedkey(plaintext, key):
    repeated_key = extend_buffer(key, len(plaintext))

    ciphertext = fixed_xor(plaintext, repeated_key)

    return ciphertext


def divide(input, denominator):
    """Take a string or bytes object and divide it into parts of "denominator"
    length.
    """
    result = []
    for i in range(0, len(input), denominator):
        chunk = input[i:i+denominator]
        result.append(chunk)
    return result


def transpose(list_of_chunks):
    max_chunklength = len(list_of_chunks[0])

    result = []

    for position in range(0, max_chunklength):
        new_chunk = b''

        for chunk in list_of_chunks:
            try:
                char = chunk[position]
                new_chunk += bytes([char])
            except IndexError:
                break

        result.append(new_chunk)

    return result


def xor_find_multichar_key(ciphertext):
    def get_aggregated_sample_score(keysize):
        number_of_samples = 6

        sample_material = ciphertext[:(keysize * number_of_samples)]

        chunks = divide(sample_material, keysize)

        total_score = 0

        # After advise from Rami__ in the #cryptopals channel on Freenode, I
        # have chosen to take a total of six samples and compare every
        # combination of these samples.
        for (x, y) in combinations(chunks, 2):
            total_score += hamming_distance(x, y)

        normalized_score = total_score / keysize

        return normalized_score


    def determine_keysize():
        keysize_candidates = []

        for i in range(2, 41):
            keysize_candidates.append((i, get_aggregated_sample_score(i)))

        best_candidate = min(keysize_candidates, key=itemgetter(1))

        keysize = best_candidate[0]

        return keysize


    keysize = determine_keysize()

    key_material = transpose(divide(ciphertext, keysize))

    plaintext = b''

    for char in key_material:
        char_value = xor_find_singlechar_key(char)["key"]
        plaintext += bytes([char_value])

    return plaintext


def pkcs7pad(input_bytes, k):
    # Source: RFC 2315, section 10.3, note #2
    input_length = len(input_bytes)
    if input_length == k:
        result = input_bytes
    else:
        n = k - (input_length % k)
        result = input_bytes + (n * bytes([n]))
    return result


def aes_128_cbc_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)

    ciphertext = b''

    diffblock = iv

    for plaintext_chunk in divide(plaintext, 16):
        xor_bytes = fixed_xor(plaintext_chunk, diffblock)

        current_ciphertext_chunk = cipher.encrypt(xor_bytes)

        ciphertext += current_ciphertext_chunk

        diffblock = current_ciphertext_chunk

    return ciphertext


def aes_128_cbc_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = b''

    diffblock = iv

    for chunk in divide(ciphertext, 16):
        xor_bytes = cipher.decrypt(chunk)

        current_plaintext_chunk = fixed_xor(xor_bytes, diffblock)

        plaintext += current_plaintext_chunk

        diffblock = chunk

    return plaintext


def nearest_multiple(n, base):
    # Based on code from http://stackoverflow.com/a/2272174
    return int(base * round(float(n)/base))


def ecb_or_cbc(ciphertext):
    """Detect if a ciphertext is encrypted with ECB or CBC."""

    # In challenges 7-12 the crypto mode is either ECB or CBC. So any
    # ciphertext with no repeating blocks is considered to be encrypted with
    # CBC.

    mode = ''

    chunks = divide(ciphertext, 16)

    total_score = 0

    for c in set(chunks):
        score = chunks.count(c)
        if score > 1:
            total_score += score

    if total_score > 1:
        mode = 'ecb'
    else:
        mode = 'cbc'

    return mode
