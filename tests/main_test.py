#!/usr/bin/env python3

# Copyright 2014 Carl Winbäck. See the COPYING file at the top-level directory
# of this distribution.

import pytest

from libpals.util import (
    xor_find_singlechar_key,
    hamming_distance,
    fixed_xor,
    transpose,
    pkcs7pad,
    nearest_multiple,
    pkcs7pad_remove
)

def test_xor_find_singlechar_key():
    input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    ciphertext = bytes.fromhex(input)
    result = xor_find_singlechar_key(ciphertext)
    assert result['key']  == 88
    assert result['plaintext']  == b"Cooking MC's like a pound of bacon"


def test_hamming_distance_a():
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37


def test_hamming_distance_b():
    assert hamming_distance(b'\x00\x00', b'\xff\xff') == 16


def test_fixed_xor():
    input = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    key = bytes.fromhex("686974207468652062756c6c277320657965")
    assert fixed_xor(input, key) == b"the kid don't play"


def test_transpose_2():
    chunks = [b'AN', b'BO', b'CP', b'DQ', b'ER', b'FS', b'GT', b'HU', b'IV',
              b'JW', b'KX', b'LY', b'MZ']
    assert transpose(chunks) == [b'ABCDEFGHIJKLM', b'NOPQRSTUVWXYZ']


def test_transpose_3():
    chunks = [b'AJS', b'BKT', b'CLU', b'DMV', b'ENW', b'FOX', b'GPY', b'HQZ',
              b'IR']
    assert transpose(chunks) == [b'ABCDEFGHI', b'JKLMNOPQR', b'STUVWXYZ']


def test_transpose_4():
    chunks = [b'AHOU', b'BIPV', b'CJQW', b'DKRX', b'ELSY', b'FMTZ', b'GN']
    assert transpose(chunks) == [b'ABCDEFG', b'HIJKLMN', b'OPQRST', b'UVWXYZ']


def test_padding_2_2():
    assert pkcs7pad(b'=)', 2) == b'=)\x02\x02'


def test_pkcs7pad_15_16():
    expected_bytes = b'MY NOSE IS NUMB\x01'
    assert pkcs7pad(b'MY NOSE IS NUMB', 16) == expected_bytes


def test_pkcs7pad_16_16():
    expected_bytes = b'MY NOSE IS NUMB!\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    assert pkcs7pad(b'MY NOSE IS NUMB!', 16) == expected_bytes


def test_pkcs7pad_24_18():
    expected_result = b'TAILFINS!! ... click ...\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
    assert pkcs7pad(b'TAILFINS!! ... click ...', 18) == expected_result


def test_pkcs7pad_16_20():
    expected_bytes = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pkcs7pad(b'YELLOW SUBMARINE', 20) == expected_bytes


def test_pkcs7pad_24_32():
    expected_result = b'Bo Derek ruined my life!\x08\x08\x08\x08\x08\x08\x08\x08'
    assert pkcs7pad(b'Bo Derek ruined my life!', 32) == expected_result


def test_pkcs7pad_3_1():
    with pytest.raises(ValueError) as excinfo:
        pkcs7pad(b'FOO', 1)
    assert 'Invalid value for ”k”.' in str(excinfo.value)


def test_pkcs7pad_remove_2():
    assert pkcs7pad_remove(b'=)\x02\x02') == b'=)'


def test_pkcs7pad_remove_4a():
    padded_bytes = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pkcs7pad_remove(padded_bytes) == b'YELLOW SUBMARINE'


def test_pkcs7pad_remove_4b():
    padded_bytes = b'ICE ICE BABY\x04\x04\x04\x04'
    assert pkcs7pad_remove(padded_bytes) == b'ICE ICE BABY'


def test_pkcs7pad_remove_invalid_a():
    with pytest.raises(ValueError) as excinfo:
        pkcs7pad_remove(b'YELLOW SUBMARINE\x00\x04\x04\x04')
    assert 'Invalid padding.' in str(excinfo.value)


def test_pkcs7pad_remove_invalid_b():
    with pytest.raises(ValueError) as excinfo:
        pkcs7pad_remove(b'ICE ICE BABY\x05\x05\x05\x05')
    assert 'Invalid padding.' in str(excinfo.value)


def test_pkcs7pad_remove_invalid_b():
    with pytest.raises(ValueError) as excinfo:
        pkcs7pad_remove(b'ICE ICE BABY\x01\x02\x03\x04')
    assert 'Invalid padding.' in str(excinfo.value)


def test_pkcs7pad_3_256():
    with pytest.raises(ValueError) as excinfo:
        pkcs7pad(b'FOO', 256)
    assert 'Invalid value for ”k”.' in str(excinfo.value)


def test_nearest_multiple_5():
    assert nearest_multiple(34, 5) == 35


def test_nearest_multiple_66():
    assert nearest_multiple(79, 66) == 132


def test_nearest_multiple_16():
    assert nearest_multiple(0, 16) == 0
