# Advanced Encryption Standard (AES)

This C++ implementation provides support for the Advanced Encryption Standard (AES) with different operation modes. The library is designed to work with AES key sizes of 128, 192, and 256 bits.

## Clone Repository:

```shell
git clone https://github.com/Shayhha/AES
```

## Features

- AES-128, AES-192, and AES-256 encryption/decryption support.
- Multiple operation modes, including ECB, CBC, CFB, OFB, and CTR.
- Automatic detection of the AES key size.
- Efficient and secure encryption/decryption algorithms.
- Support for PKCS7 padding.

## Usage

### AES Modes

The library supports the following AES modes:

- **ECB (Electronic Codebook)**: Simplest mode, where each block of plaintext is encrypted independently.
- **CBC (Cipher Block Chaining)**: Each block is XORed with the previous ciphertext block before encryption.
- **CFB (Cipher Feedback)**: Each block is XORed with the previous ciphertext block before encryption, then shifted.
- **OFB (Output Feedback)**: Each block is XORed with the previous block of the keystream.
- **CTR (Counter)**: A counter is used to generate a keystream, which is XORed with the plaintext.

### Key Detection

The library detects the AES key size (128, 192, or 256 bits) based on the length of the provided key.

### Sample Code

```cpp
// Example code to use the AES library
#include "AES.h"

int main() {
    try {
        ///Test AES encryption and decryption///
        string plaintext = "TheKingOfNewYork";
        vector<unsigned char> plaintextVec(plaintext.begin(), plaintext.end());
        vector<unsigned char> keyVec = AES::Create_Key(128);
        vector<unsigned char> ivVec = AES::Create_IV(16);
        cout << "Plain Text:" << endl;
        cout << AES::VectorToHex(plaintextVec) << endl;
        cout << "Cipher Text:" << endl;
        plaintextVec = AES::Encrypt_CBC(plaintextVec, keyVec, ivVec);
        cout << AES::VectorToHex(plaintextVec) << endl;
        cout << "Original Text:" << endl;
        plaintextVec = AES::Decrypt_CBC(plaintextVec, keyVec, ivVec);
        cout << AES::VectorToHex(plaintextVec) << endl;
        AES::PrintVector(plaintextVec);
    }
    catch (const invalid_argument& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}
```

## Contact

For questions or feedback, please contact [shayhha@gmail.com](mailto:shayhha@gmail.com).

## License

This AES library is released under the [MIT License](LICENSE.txt).

© All rights reserved to Shayhha (Shay Hahiashvili).
