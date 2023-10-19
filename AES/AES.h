#ifndef _AES_H
#define _AES_H
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string.h>
#include <vector>
#include <fstream>
#include <cstdlib>
#include <iomanip> 

using namespace std;

class AES {
private:
	static const unsigned char SBOX[16][16]; //represent the SBOX table for AES
	static const unsigned char INVSBOX[16][16]; //represent the inverse SBOX table for AES
	static const unsigned char GaloisMult[15][256]; //represents the Galois multiplication tables for AES
	static const int Nb = 4; //number of columns in the state (always 4 for AES)
	static int Nk; //number of 32-bit words in the key 
	static int Nr; //number of rounds (AES-128 has 10 rounds, AES-192 has 12 rounds, AES-256 has 14 rounds)
	static const size_t BlockSize = Nb * Nb; //represents the size of AES block that is always 16 bytes (128-bit)

public:
	static const vector<unsigned char> AES_Cipher(vector<unsigned char>& plaintext, vector<unsigned char>& key, const bool isDecrypt=false);
	static const vector<vector<unsigned char>> KeySchedule(const vector<unsigned char>& key, const bool isDecrypt=false);
	static void SetOperationMode(const size_t textSize, const size_t keySize);
	static void PrintVector(const vector<unsigned char>& vector);
	static void PrintMatrix(const vector<vector<unsigned char>>& matrix);
	static const vector<unsigned char> RotWord(const vector<unsigned char>& word);
	static const vector<unsigned char> SubWord(const vector<unsigned char>& word);
	static const unsigned char Rcon(const unsigned char& value);
	static const vector<unsigned char> SubBytes(vector<unsigned char>& state, const bool isDecrypt = false);
	static const vector<unsigned char> ShiftRows(vector<unsigned char>& state, const bool isDecrypt=false);
	static const vector<unsigned char> MixColumns(vector<unsigned char>& state, const bool isDecrypt = false);
	static const vector<unsigned char> XOR(vector<unsigned char>& first, vector<unsigned char>& second, const bool immutable=false);
	static const vector<vector<unsigned char>> SplitIntoKeyWords(const vector<unsigned char>& key);
};
#endif