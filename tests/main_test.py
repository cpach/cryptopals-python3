#!/usr/bin/env python3

from libpals.util import xor_find_singlechar_key

def test_xor_find_singlechar_key():
    input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    ciphertext = bytes.fromhex(input)
    result = xor_find_singlechar_key(ciphertext)
    assert result['key']  == 88
    assert result['plaintext']  == b"Cooking MC's like a pound of bacon"
