#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <random>

using namespace std;

class Encryption {
public:
    static vector<unsigned char> GenerateRandomKey();
    static string Encrypt(const string& plaintext, vector<unsigned char>& key);
    static string Decrypt(const string& ciphertext, vector<unsigned char>& key);
};

#endif
