#ifndef _AES_H
#define _AES_H
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string.h>
#include <vector>
#include <random>
#include <fstream>
#include <cstdlib>
#include <iomanip> 

using namespace std;

/**
 * @file AES.h
 * @brief � AES (Advanced Encryption Standard) class.
 * @brief � The AES class supports both encryption and decryption, and it follows the AES specification.
 * @brief � This class provides functionality for AES encryption and decryption in ECB, CBC, CFB, OFB and CTR modes.
 * @brief � This class automatically detects the key size for AES encryption and decryption, supports AES-128, AES-192 and AES-256.
 */
class AES {
private:
	/**
	 * @brief � Represents the SBOX table of AES encryption.
	 */
	static const unsigned char SBOX[16][16];

	/**
	 * @brief � Represents the inverse SBOX table of AES encryption.
	 */
	static const unsigned char INVSBOX[16][16];

	/**
	 * @brief � Galois multiplication tables for AES MixColumns function.
	 */
	static const unsigned char GaloisMult[15][256];

	/**
	 * @brief � number of columns in the state (always 4 for AES).
	 */
	static const size_t Nb = 4;

	/**
	 * @brief � number of 32-bit words in the key.
	 */
	static size_t Nk;

	/**
	 * @brief � number of rounds (AES-128 has 10 rounds, AES-192 has 12 rounds, AES-256 has 14 rounds).
	 */
	static size_t Nr;

	/**
	 * @brief � represents the size of AES block that is always 16 bytes (128-bit).
	 */
	static const size_t BlockSize = Nb * Nb;

protected:
	/**
	 * @brief � Function that performs AES encryption on given text using specified round keys, supports AES-128, AES-192 and AES-256.
	 * @brief � This function performs AES encryption with fixed block size of 16 bytes (128-bit).
	 * @param � vector<unsigned char> text
	 * @param � vector<vector<unsigned char>> roundKeys
	 * @return � vector<unsigned char> cipherText
	 */
	static const vector<unsigned char> EncryptBlock(vector<unsigned char>& text, const vector<vector<unsigned char>>& roundKeys);

	/**
	 * @brief � Function that performs AES decryption on given text using specified round keys, supports AES-128, AES-192 and AES-256.
	 * @brief � This function performs AES decryption with fixed block size of 16 bytes (128-bit).
	 * @param � vector<unsigned char> text
	 * @param � vector<vector<unsigned char>> roundKeys
	 * @return � vector<unsigned char> decipherText
	 */
	static const vector<unsigned char> DecryptBlock(vector<unsigned char>& text, const vector<vector<unsigned char>>& roundKeys);

	/**
	 * @brief � Function for generating round keys for AES encryption, supports AES-128, AES-192 and AES-256.
	 * @param � vector<unsigned char> key
	 * @return � vector<vector<unsigned char>> roundKeys
	 */
	static const vector<vector<unsigned char>> KeySchedule(const vector<unsigned char>& key);

	/**
	 * @brief � Function that handles the operation mode of AES encryption.
	 * @param � size_t keySize
	 * @throws � invalid_argument thrown if given keySize is invalid.
	 */
	static void SetOperationMode(const size_t keySize);

	/**
	 * @brief � Function that rotates a vector element (byte) to the left.
	 * @param � vector<unsigned char> word
	 * @return � vector<unsigned char> rotatedWord
	 */
	static const vector<unsigned char> RotWord(vector<unsigned char>& word);

	/**
	 * @brief � Function that substitutes each byte in a word using the SBOX.
	 * @param � vector<unsigned char> word
	 * @return � vector<unsigned char> subWord
	 */
	static const vector<unsigned char> SubWord(vector<unsigned char>& word);

	/**
	 * @brief � Function that returns the Rcon value given original value for key schedule.
	 * @param � unsigned char value
	 * @return � unsigned char rconValue
	 */
	static const unsigned char Rcon(const unsigned char& value);

	/**
	 * @brief � Function for substitute bytes in AES encryption, both for encryption and decryption.
	 * @param � vector<unsigned char> state
	 * @param � bool inverse
	 * @return � vector<unsigned char> subState
	 */
	static const vector<unsigned char> SubBytes(vector<unsigned char>& state, const bool inverse = false);

	/**
	 * @brief � Function for shifting rows in AES encryption, both for encryption and decryption.
	 * @param � vector<unsigned char> state
	 * @param � bool inverse
	 * @return � vector<unsigned char> shiftedState
	 */
	static const vector<unsigned char> ShiftRows(vector<unsigned char>& state, const bool inverse = false);

	/**
	 * @brief � Function for mixing columns using GaloisMult tables for AES encryption, both for encryption and decryption.
	 * @param � vector<unsigned char> state
	 * @param � bool inverse
	 * @return � vector<unsigned char> mixedState
	 */
	static const vector<unsigned char> MixColumns(vector<unsigned char>& state, const bool inverse = false);

	/**
	 * @brief � Function for XOR operation between two vectors in same size, vectors immutable if flag is set.
	 * @param � vector<unsigned char> first
	 * @param � vector<unsigned char> second
	 * @param � bool immutable
	 * @return � vector<unsigned char> xor
	 */
	static const vector<unsigned char> XOR(vector<unsigned char>& first, const vector<unsigned char>& second, const bool immutable = false);

public:
	/**
	 * @brief � Function that performs AES encryption on given text using specified key, supports AES-128, AES-192 and AES-256.
	 * @brief � This function performs AES encryption with fixed block size of 16 bytes (128-bit).
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @return � vector<unsigned char> cipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 */
	static const vector<unsigned char> Encrypt(vector<unsigned char>& text, const vector<unsigned char>& key);

	/**
	 * @brief � Function that performs AES decryption on given text using specified key, supports AES-128, AES-192 and AES-256.
	 * @brief � This function performs AES decryption with fixed block size of 16 bytes (128-bit).
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @return � vector<unsigned char> decipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 */
	static const vector<unsigned char> Decrypt(vector<unsigned char>& text, const vector<unsigned char>& key);

	/**
	 * @brief � Function that performs AES encryption in ECB mode on given text using specified key.
	 * @brief � ECB mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports PKCS7 padding.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @return � vector<unsigned char> cipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 */
	static const vector<unsigned char> Encrypt_ECB(vector<unsigned char>& text, const vector<unsigned char>& key);

	/**
	 * @brief � Function that performs AES decryption in ECB mode on given text using specified key.
	 * @brief � ECB mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports PKCS7 padding.
	 * @brief � ECB decryption mode requires text to be a multiple of 16 bytes in length.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @return � vector<unsigned char> decipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 */
	static const vector<unsigned char> Decrypt_ECB(vector<unsigned char>& text, const vector<unsigned char>& key);

	/**
	 * @brief � Function that performs AES encryption in CBC mode on given text using specified key and initialization vector.
	 * @brief � CBC mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports PKCS7 padding.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> cipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Encrypt_CBC(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function that performs AES decryption in CBC mode on given text using specified key and initialization vector.
	 * @brief � CBC mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports PKCS7 padding.
	 * @brief � CBC decryption mode requires text to be a multiple of 16 bytes in length.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> decipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Decrypt_CBC(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function that performs AES encryption in CFB mode on given text using specified key and initialization vector.
	 * @brief � CFB mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports text in any size.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> cipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Encrypt_CFB(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function that performs AES decryption in CFB mode on given text using specified key and initialization vector.
	 * @brief � CFB mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports text in any size.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> decipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Decrypt_CFB(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function that performs AES encryption in OFB mode on given text using specified key and initialization vector.
	 * @brief � OFB mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports text in any size.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> cipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Encrypt_OFB(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function that performs AES decryption in OFB mode on given text using specified key and initialization vector.
	 * @brief � OFB mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports text in any size.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> decipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Decrypt_OFB(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function that performs AES encryption in CTR mode on given text using specified key and initialization vector.
	 * @brief � CTR mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports text in any size.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> cipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Encrypt_CTR(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function that performs AES decryption in CTR mode on given text using specified key and initialization vector.
	 * @brief � CTR mode supports AES-128, AES-192 and AES-256.
	 * @brief � Supports text in any size.
	 * @param � vector<unsigned char> text
	 * @param � vector<unsigned char> key
	 * @param � vector<unsigned char> iv
	 * @return � vector<unsigned char> decipherText
	 * @throws � invalid_argument thrown if given text is invalid.
	 * @throws � invalid_argument thrown if given key is invalid.
	 * @throws � invalid_argument thrown if given iv is invalid.
	 */
	static const vector<unsigned char> Decrypt_CTR(vector<unsigned char>& text, const vector<unsigned char>& key, const vector<unsigned char>& iv);

	/**
	 * @brief � Function for creating a vector.
	 * @param � size_t vecSize
	 * @return � vector<unsigned char> vec
	 */
	static const vector<unsigned char> Create_Vector(const size_t vecSize);

	/**
	 * @brief � Function for creating an AES key.
	 * @brief � Supports AES-128, AES-192 and AES-256 keys.
	 * @brief � Returns default AES-128 key if invalid size given.
	 * @param � size_t keySize
	 * @return � vector<unsigned char> key
	 */
	static const vector<unsigned char> Create_Key(const size_t keySize = 128);

	/**
	 * @brief � Function for creating an initialization vector.
	 * @return � vector<unsigned char> iv
	 */
	static const vector<unsigned char> Create_IV();

	/**
	 * @brief � Function for clearing a vector security.
	 * @param � vector<unsigned char> vec
	 */
	static void ClearVector(vector<unsigned char>& vec);

	/**
	 * @brief � Function for clearing a vector of vectors security.
	 * @param � vector<vector<unsigned char>> vec
	 */
	static void ClearVector(vector<vector<unsigned char>>& vec);

	/**
	 * @brief � Function for printing a vector in hexadecimal.
	 * @param � vector<unsigned char> vec
	 */
	static void PrintVector(const vector<unsigned char>& vec);

	/**
	 * @brief � Function for printing a vector of vectors in hexadecimal.
	 * @param � vector<vector<unsigned char>> vec
	 */
	static void PrintVector(const vector<vector<unsigned char>>& vec);
};
#endif