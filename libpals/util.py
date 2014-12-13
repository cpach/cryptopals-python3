#!/usr/bin/env python3

# Copyright 2016 Carl Winbäck. See the COPYING file at the top-level directory
# of this distribution.

from Crypto.Cipher import AES
from collections import Counter
from operator import itemgetter
from itertools import combinations
from base64 import b64decode
from os import urandom
from random import SystemRandom


class Oracle(object):
    def __init__(self):
        encoded_secret = (b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd2'
                          b'4gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBz'
                          b'dGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IH'
                          b'N0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
        self.__SECRET_KEY = urandom(16)
        self._SECRET_MESSAGE = b64decode(encoded_secret)

    def encrypt(self, input_bytes):
        cipher = AES.new(self.__SECRET_KEY, AES.MODE_ECB)
        payload = self._generate_payload(input_bytes)
        ciphertext = cipher.encrypt(pkcs7pad(payload, 16))
        return ciphertext


class StaticOracle(Oracle):

    def _generate_payload(self, user_input):
        return user_input + self._SECRET_MESSAGE


class IrregularOracle(Oracle):

    def _generate_random_prefix(self):
        return urandom(SystemRandom().randint(1, 40))

    def _generate_payload(self, user_input):
        # I opted to make IrregularOracle change the prefix on every call,
        # mainly because I thought it was more fun that way.
        random_prefix = self._generate_random_prefix()
        return random_prefix + user_input + self._SECRET_MESSAGE


class OracleCracker(object):
    def __init__(self, oracle):
        # For the IrregularOracle we will assume the blocksize is 16. For
        # StaticOracle, the blocksize will be determined.
        self.blocksize = 16
        self.oracle = oracle
        self._filler_offset = 0

    def __detect_padding_length(self):
        initial_length = len(self._get_desired_output(b''))
        current_length = 0
        i = 0
        while current_length <= initial_length:
            current_length = len(self._get_desired_output(i * b'A'))
            i += 1
        padding_length = i - 1
        return padding_length

    def _detect_plaintext_length(self):
        max_possible_length = len(self._get_desired_output(b''))
        padding_length = self.__detect_padding_length()
        actual_length = (max_possible_length - padding_length -
                         self._filler_offset)
        return actual_length

    def crack(self):
        plaintext = b''
        plaintext_length = self._detect_plaintext_length()
        for ciphertext_index in range(1, plaintext_length + 1):
            block_end = (nearest_multiple(ciphertext_index, self.blocksize) +
                         self._filler_offset)
            block_start = block_end - self.blocksize
            filler_length = block_end - ciphertext_index - self._filler_offset
            filler = b'A' * filler_length
            byte_dictionary = {}
            for byte_index in range(0, 256):
                char = bytes([byte_index])
                teaser_block = (b'A' * filler_length) + plaintext + char
                ciphertext = self._get_desired_output(teaser_block)
                byte_dictionary[ciphertext[block_start:block_end]] = char
            comparison_ciphertext = self._get_desired_output(filler)
            comparison_block = comparison_ciphertext[block_start:block_end]
            current_plaintext_byte = byte_dictionary[comparison_block]
            plaintext += current_plaintext_byte
        return plaintext


class StaticOracleCracker(OracleCracker):

    def __init__(self, *args):
        super().__init__(*args)
        self.blocksize = self.__detect_blocksize()

    def __detect_blocksize(self):
        input_bytes = b'A'
        initial_length = len(self.oracle.encrypt(b''))
        step = 0
        while step <= initial_length:
            input_bytes += b'A'
            step = len(self.oracle.encrypt(input_bytes))
        blocksize = step - initial_length
        return blocksize

    def _get_desired_output(self, input_bytes):
        return self.oracle.encrypt(input_bytes)


class IrregularOracleCracker(OracleCracker):

    def __init__(self, *args):
        super().__init__(*args)
        self._filler_offset = 32
        self._idblock_plaintext = urandom(16)
        self._idblock_ciphertext = self.\
          _determine_ciphertext(self._idblock_plaintext)

    def _determine_ciphertext(self, plaintext):
        """Determine likely ciphertext for a given plaintext."""
        candidates = []
        while len(candidates) < 40:
            oracle_output = self.oracle.encrypt(plaintext + plaintext)
            block_a = oracle_output[16:32]
            block_b = oracle_output[32:48]
            if block_a == block_b:
                candidates.append(block_a)
        winner = Counter(candidates).most_common(1)[0][0]
        return winner

    def _get_desired_output(self, input_bytes):
        # By using the ”ID block” we can identify ciphertexts where the prefix
        # is 16 bytes long. When the prefix is 16 bytes long we know how long
        # the padding block will be and we can determine the plaintext length.
        output = b''
        while len(output) == 0:
            ciphertext = self.oracle.encrypt(self._idblock_plaintext +
                                             input_bytes)
            if ciphertext[16:32] == self._idblock_ciphertext:
                output = ciphertext
        return output


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
    # Source: RFC 5652, section 6.3
    l = len(input_bytes)
    if k <= 1 or k >= 256:
        raise ValueError('Invalid value for ”k”.')
    n = k - (l % k)
    result = input_bytes + (n * bytes([n]))
    return result


def pkcs7pad_remove(input_bytes):
    last_byte_value = input_bytes[-1]
    length_without_padding = len(input_bytes) - last_byte_value
    expected_padding = bytes([last_byte_value]) * last_byte_value
    padding_block = input_bytes[-last_byte_value:]
    if padding_block != expected_padding:
        raise ValueError('Invalid padding.')
    return input_bytes[0:length_without_padding]


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
    """Round ”n” up to the nearest multiple of ”base”"""
    # Based on code from https://stackoverflow.com/a/8866125/3335987
    result = n if n % base == 0 else n + base - n % base
    return result


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


def numberlist_to_bytes(list_of_numbers):
    result = b''
    for char in list_of_numbers:
        if not 0 <= char <= 255:
            raise ValueError('All integers need to be in the range 0-255.')
        result += bytes([char])
    return result
