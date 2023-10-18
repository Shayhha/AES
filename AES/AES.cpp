#include "AES.h"


//set default values of Nk and Nr to AES-128
int AES::Nk = 4; //number of 32-bit words in the key (AES-128)
int AES::Nr = 10; //number of rounds (AES-128 has 10 rounds)


/// <summary>
/// Represents the SBOX of AES encryption.
/// </summary>
const unsigned char AES::SBOX[16][16] = {
  //  _0    _1    _2    _3    _4    _5    _6    _7    _8    _9    _A    _B    _C    _D    _E    _F    //
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76}, //_0
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0}, //_1
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15}, //_2
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75}, //_3
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84}, //_4
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF}, //_5
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8}, //_6
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2}, //_7
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73}, //_8
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB}, //_9
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79}, //_A
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08}, //_B
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A}, //_C
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E}, //_D
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF}, //_E
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  //_F
};


/// <summary>
/// Represents the inverse SBOX of AES encryption.
/// </summary>
const unsigned char AES::INVSBOX[16][16] = {
  //  _0    _1    _2    _3    _4    _5    _6    _7    _8    _9    _A    _B    _C    _D    _E    _F    //
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB}, //_0
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB}, //_1
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E}, //_2
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25}, //_3
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92}, //_4
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84}, //_5
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06}, //_6
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B}, //_7
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73}, //_8
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E}, //_9
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B}, //_A
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4}, //_B
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F}, //_C
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF}, //_D
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61}, //_E
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}  //_F
};



/// <summary>
/// Function that handles the operation mode of AES encryption.
/// </summary>
/// <param name="int blockSize"></param>
void AES::SetOperationMode(const int blockSize) {
    if (blockSize == 128) { //if blockSize is 128
        AES::Nk = 4; //number of 32-bit words in the key (AES-128)
        AES::Nr = 10; //number of rounds (AES-128 has 10 rounds)
    }
    else if (blockSize == 192) { //if blockSize is 192
        AES::Nk = 6; //number of 32-bit words in the key (AES-192)
        AES::Nr = 12; //number of rounds (AES-192 has 12 rounds)
    }
    else if (blockSize == 256) { //if blockSize is 256
        AES::Nk = 8; //number of 32-bit words in the key (AES-256)
        AES::Nr = 14; //number of rounds (AES-256 has 14 rounds)
    }
    else //else blockSize isn't valid
        throw runtime_error("Invalid mode of operation."); //we throw a runtime error
}


/// <summary>
/// Function that rotates a vector element(byte) to the left.
/// </summary>
/// <param name="vector&lt;unsigned char&gt; word"></param>
/// <returns></returns>
vector<unsigned char> AES::RotWord(const vector<unsigned char>& word) {
    vector<unsigned char> result(Nb); //initialize a vector of size Nb
    //shift the word to the left by one position
    result[0] = word[1];
    result[1] = word[2];
    result[2] = word[3];
    result[3] = word[0];
    return result; //return result
}


/// <summary>
/// Function that substitutes each byte in a word using the SBOX.
/// </summary>
/// <param name="vector&lt;unsigned char&gt; word"></param>
/// <returns></returns>
vector<unsigned char> AES::SubWord(const vector<unsigned char>& word) {
    vector<unsigned char> result(Nb); //initialize a vector of size Nb
    for (int i = 0; i < Nb; i++) { //iterate over the word
        //we set the value from SBOX with right rotating by 4 to extract the left value and OR with 0x0F for extracting the right value
        result[i] = SBOX[word[i] >> 4][word[i] & 0x0F]; //set the value from the SBOX
    }
    return result; //return new word with SBOX values
}


/// <summary>
/// Function that returns the Rcon value given original value for key schedule.
/// </summary>
/// <param name=" unsigned char value"></param>
/// <returns></returns>
const unsigned char AES::Rcon(const unsigned char& value) {
    unsigned char result = 0x01; //initialize with 0x01 (first round constant)
    for (int i = 1; i < value; i++) {
        if (result & 0x80) //if the leftmost bit (0x80) is set
            result = (result << 1) ^ 0x11B; //XOR with 0x11B after left shifting
        else //else we left shift 
            result = result << 1; //left shift the result by one
    }
    return result; //return rcon value
}


/// <summary>
/// Function for substitute bytes in AES encryption, both for encryption and decryption.
/// </summary>
/// <param name="vector&lt;unsigned char&gt; state"></param>
/// <param name="bool isDecrypt"></param>
/// <returns></returns>
vector<unsigned char> AES::SubBytes(vector<unsigned char>& state, const bool isDecrypt) {
    if (!isDecrypt) { //perform substitute bytes for encryption
        for (size_t i = 0; i < state.size(); i++) //iterate over state vector
            state[i] = SBOX[state[i] >> 4][state[i] & 0x0F]; //set correct value from SBOX
    }
    else { //perform substitute bytes for decryption
        for (size_t i = 0; i < state.size(); i++) //iterate over state vector
            state[i] = INVSBOX[state[i] >> 4][state[i] & 0x0F]; //set correct value from INVSBOX
    }
    return state; //return new state vector after substitute bytes
}


/// <summary>
/// Function for shifting rows in AES encryption, both for encryption and decryption.
/// </summary>
/// <param name="vector&lt;unsigned char&gt; state"></param>
/// <param name="bool isDecrypt"></param>
/// <returns></returns>
vector<unsigned char> AES::ShiftRows(vector<unsigned char>& state, const bool isDecrypt) {
    if (!isDecrypt) { //perform shift rows for encryption
        //swap elements in second row
        swap(state[4], state[5]);
        swap(state[5], state[6]);
        swap(state[6], state[7]);
        //swap elements in third row
        swap(state[8], state[10]);
        swap(state[9], state[11]);
        //swap elements in fourth row
        swap(state[14], state[15]);
        swap(state[13], state[14]);
        swap(state[12], state[13]);
    }
    else { //perform inverse shift rows for decryption
        //swap elements in second row
        swap(state[6], state[7]);
        swap(state[5], state[6]);
        swap(state[4], state[5]);
        //swap elements in third row
        swap(state[8], state[10]);
        swap(state[9], state[11]);
        //swap elements in fourth row
        swap(state[12], state[13]);
        swap(state[13], state[14]);
        swap(state[14], state[15]);
    }
    return state; //return shifted state vector
}


/// <summary>
/// Function for XOR operation between two vectors in same size.
/// </summary>
/// <param name="vector&lt;unsigned char&gt; first"></param>
/// <param name="vector&lt;unsigned char&gt; second"></param>
/// <returns></returns>
vector<unsigned char> AES::XOR(const vector<unsigned char>& first, const vector<unsigned char>& second) {
    vector<unsigned char> result;
    if (first.size() == second.size()) { //if same size we continue
        result.reserve(first.size()); //reserve memory for vector
        for (size_t i = 0; i < first.size(); i++) { //iterate over the vectors
            result.push_back(first[i] ^ second[i]); //push to new vector the new XOR'ed elements 
        }
    }
    return result; //return result
}


/// <summary>
/// Function that splits given vector into AES blocks (4 bytes).
/// </summary>
/// <param name="vector&lt;unsigned char&gt; key"></param>
/// <returns></returns>
vector<vector<unsigned char>> AES::SplitIntoKeyWords(const vector<unsigned char>& key) {
    vector<vector<unsigned char>> KeyWordArray; //initialize new vector
    for (int i = 0; i < key.size(); i += Nb) { //iterate over the given key vector
        vector<unsigned char> block(key.begin() + i, key.begin() + i + Nb); //split the vector into blocks
        KeyWordArray.push_back(block); //push the block to the new vector
    }
    return KeyWordArray; //return the new vector
}


/// <summary>
/// Function for generating round keys for AES encryption (AES-128, AES-192, AES-256).
/// </summary>
/// <param name="vector&lt;unsigned char&gt; key"></param>
/// <param name="bool isDecrypt"></param>
/// <returns></returns>
const vector<vector<unsigned char>> AES::KeySchedule(const vector<unsigned char>& key, const bool isDecrypt) {
    vector<vector<unsigned char>> roundKeysMatrix; //initialize the matrix of round keys (each represented as a vector of unsigned char)
    vector<unsigned char> roundKeysVector; //initialize new round keys vector
    copy(key.begin(), key.end(), back_inserter(roundKeysVector)); //add initial key to roundKey vector

    //iterate over the round keys vector in the specified number of rounds and generate round keys
    for (int i = 1; i <= Nr; i++) {
        vector<unsigned char> previousKey(roundKeysVector.begin() + roundKeysVector.size() - (Nb * Nk), roundKeysVector.end()); //retrieve previous key from roundKeysVector
        vector<vector<unsigned char>> currentWord = SplitIntoKeyWords(previousKey); //split key into 32-bit keywords for ease of use
        vector<unsigned char> temp = SubWord(RotWord(currentWord[Nk - 1])); //apply SubWord and RotWord operation on current word and save it in temp vector
        temp[0] ^= Rcon(i); //XOR temp vector with Rcon value 
        //now we need to iterate over Nk (number of keywords) to generate the key
        for (int j = 0; j < Nk; j++) {
            temp = XOR(temp, currentWord[j]); //call our XOR function to apply XOR operation on temp and currentWord vectors
            copy(temp.begin(), temp.end(), back_inserter(roundKeysVector)); //add our word into the round keys vector
            if (Nk > 6 && j == 3) //for AES-256 we need to apply SubWord again for added security half way of the generation
                temp = SubWord(temp); //apply the SubWord function again for AES-256
        }
    }
    roundKeysVector.erase(roundKeysVector.begin() + (Nr + 1) * 16 , roundKeysVector.end()); //remove the extra bytes if present (on AES-192 and AES-256)

    //finally we add roundKeysVector keys to roundKeysMatrix for later use in AES encryption
    for (size_t i = 0; i < roundKeysVector.size(); i += 16) { //iterate over our round keys vector
        vector<unsigned char> key(roundKeysVector.begin() + i, roundKeysVector.begin() + min(roundKeysVector.size(), i + 16)); //getting each key (128-bit) from beginning of vector
        roundKeysMatrix.push_back(key); //add key to the matrix
    }

    if (isDecrypt) //if decrypting
        reverse(roundKeysMatrix.begin(), roundKeysMatrix.end()); //reverse the order of round keys for decryption

    return roundKeysMatrix; //return our roundKeysMatrix for AES operation
}



int main() {
    //vector<unsigned char> key128 = {
    //0x2b, 0x7e, 0x15, 0x16,
    //0x28, 0xae, 0xd2, 0xa6,
    //0xab, 0xf7, 0x97, 0x22,
    //0x33, 0x54, 0x91, 0xf5
    //};

    vector<unsigned char> key128(16, 0x00);
    //AES::SetOperationMode(256);
    vector<vector<unsigned char>> matrix = AES::KeySchedule(key128);

    for (const vector<unsigned char>& row : matrix) {
        //iterate through the inner vector (row)
        for (unsigned char element : row) {
            //set the output stream to hexadecimal mode and specify the width and fill
            cout << hex << setw(2) << setfill('0') << static_cast<int>(element) << " ";
        }
        cout << dec << endl; //restore the output stream to decimal mode after each row
    }

    ///test of shift rows///
    //vector<unsigned char> lol = {
    //0x34, 0x02, 0xD6, 0x30,
    //0xD8, 0x0D, 0x2F, 0x60,
    //0x0D, 0x44, 0x60, 0xD9,
    //0x1C, 0x3F, 0x5C, 0x5A
    //};
    //lol = AES::ShiftRows(lol);
    //    for (unsigned char element : lol) {
    //        //set the output stream to hexadecimal mode and specify the width and fill
    //        cout << hex << setw(2) << setfill('0') << static_cast<int>(element) << " ";
    //    }
    //    cout << dec << endl; //restore the output stream to decimal mode after each row

    return 0;
}