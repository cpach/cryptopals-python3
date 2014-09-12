#!/usr/bin/env python3

from operator import itemgetter

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

    result = b''

    for position in range(0, max_chunklength):
        for chunk in list_of_chunks:
            try:
                char = chunk[position]
                result += bytes([char])
            except IndexError:
                break

    return result
