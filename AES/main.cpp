#include "AES.h"


int main() {
    ///test key schedule///
    //vector<unsigned char> key1(16, 0x00);
    //AES::SetOperationMode(key1.size());
    //vector<vector<unsigned char>> keys = AES::KeySchedule(key1);
    //AES::PrintVector(keys);

    ///test AES encryption and decryption///
    string plaintext = "TheKingOfNewYork";
    vector<unsigned char> plaintextVec(plaintext.begin(), plaintext.end());
    vector<unsigned char> keyVec = AES::Create_Key(128);
    vector<unsigned char> ivVec = AES::Create_IV();
    cout << "Plain Text:" << endl;
    AES::PrintVector(plaintextVec);
    try {
        cout << "Cipher Text:" << endl;
        //plaintextVec = AES::Encrypt_ECB(plaintextVec, keyVec);
        //plaintextVec = AES::Encrypt_CBC(plaintextVec, keyVec, ivVec);
        //plaintextVec = AES::Encrypt_CFB(plaintextVec, keyVec, ivVec);
        //plaintextVec = AES::Encrypt_OFB(plaintextVec, keyVec, ivVec);
        plaintextVec = AES::Encrypt_CTR(plaintextVec, keyVec, ivVec);
        AES::PrintVector(plaintextVec);
        cout << "Original Text:" << endl;
        //plaintextVec = AES::Decrypt_ECB(plaintextVec, keyVec);
        //plaintextVec = AES::Decrypt_CBC(plaintextVec, keyVec, ivVec);
        //plaintextVec = AES::Decrypt_CFB(plaintextVec, keyVec, ivVec);
        //plaintextVec = AES::Decrypt_OFB(plaintextVec, keyVec, ivVec);
        plaintextVec = AES::Decrypt_CTR(plaintextVec, keyVec, ivVec);
        AES::PrintVector(plaintextVec);
        string str(plaintextVec.begin(), plaintextVec.end());
        cout << str << endl;
    }
    catch (const invalid_argument& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}