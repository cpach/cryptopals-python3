#!/usr/bin/env python3

from libpals.util import (
    xor_find_singlechar_key,
    hamming_distance,
    fixed_xor,
    transpose
)

def test_xor_find_singlechar_key():
    input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    ciphertext = bytes.fromhex(input)
    result = xor_find_singlechar_key(ciphertext)
    assert result['key']  == 88
    assert result['plaintext']  == b"Cooking MC's like a pound of bacon"


def test_hamming_distance():
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37


def test_fixed_xor():
    input = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    key = bytes.fromhex("686974207468652062756c6c277320657965")
    assert fixed_xor(input, key) == b"the kid don't play"


def test_transpose():
    chunks = [b'adg', b'beh', b'cfi']
    assert transpose(chunks) == b'abcdefghi'
