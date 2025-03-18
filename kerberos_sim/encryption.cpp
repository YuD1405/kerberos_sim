//#include "encryption.h"
//#include <openssl/evp.h>
//#include <openssl/rand.h>
//#include <iostream>
//#include <vector>
//#include <cstring>
//
//vector<unsigned char> Encryption::GenerateRandomKey() {
//    vector<unsigned char> key(32); // 256-bit key
//    if (RAND_bytes(key.data(), key.size()) != 1) {
//        cerr << "[ERROR] Không thể tạo khóa ngẫu nhiên!\n";
//        exit(EXIT_FAILURE);
//    }
//    return key;
//}
//
//string Encryption::Encrypt(const string& plaintext, const vector<unsigned char>& key) {
//    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//    if (!ctx) {
//        cerr << "[ERROR] Không thể tạo context mã hóa!" << endl;
//        return "";
//    }
//
//    // Khởi tạo mã hóa AES-256-ECB (không cần IV)
//    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr) != 1) {
//        cerr << "[ERROR] Lỗi khi khởi tạo mã hóa!" << endl;
//        EVP_CIPHER_CTX_free(ctx);
//        return "";
//    }
//
//    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_ecb()));
//    int len = 0, ciphertext_len = 0;
//
//    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
//        cerr << "[ERROR] Lỗi khi mã hóa dữ liệu!" << endl;
//        EVP_CIPHER_CTX_free(ctx);
//        return "";
//    }
//    ciphertext_len += len;
//
//    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
//        cerr << "[ERROR] Lỗi khi hoàn tất mã hóa!" << endl;
//        EVP_CIPHER_CTX_free(ctx);
//        return "";
//    }
//    ciphertext_len += len;
//
//    EVP_CIPHER_CTX_free(ctx);
//    return string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
//}
//
//string Encryption::Decrypt(const string& ciphertext, const vector<unsigned char>& key) {
//    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//    if (!ctx) {
//        cerr << "[ERROR] Không thể tạo context giải mã!" << endl;
//        return "";
//    }
//
//    // Khởi tạo AES-256-ECB (không cần IV)
//    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr) != 1) {
//        cerr << "[ERROR] Lỗi khi khởi tạo giải mã!" << endl;
//        EVP_CIPHER_CTX_free(ctx);
//        return "";
//    }
//
//    vector<unsigned char> plaintext(ciphertext.size());
//    int len = 0, plaintext_len = 0;
//
//    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
//        cerr << "[ERROR] Lỗi khi giải mã dữ liệu!" << endl;
//        EVP_CIPHER_CTX_free(ctx);
//        return "";
//    }
//    plaintext_len += len;
//
//    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
//        cerr << "[ERROR] Lỗi khi hoàn tất giải mã!" << endl;
//        EVP_CIPHER_CTX_free(ctx);
//        return "";
//    }
//    plaintext_len += len;
//
//    EVP_CIPHER_CTX_free(ctx);
//    return string(plaintext.begin(), plaintext.begin() + plaintext_len);
//}

#include "encryption.h"
#include <iostream>

vector<unsigned char> Encryption::GenerateRandomKey() {
    vector<unsigned char> key(16); // 16 bytes (128-bit) key
    for (auto& c : key) {
        c = 'A' + rand() % 26;  // random ký tự từ A-Z
    }
    return key;
}

string Encryption::Encrypt(const string& plaintext, const vector<unsigned char>& key) {
    string keyStr(key.begin(), key.end());
    return "encrypted_" + keyStr + "_" + plaintext;
}

string Encryption::Decrypt(const string& ciphertext, const vector<unsigned char>& key) {
    string keyStr(key.begin(), key.end());
    string prefix = "encrypted_" + keyStr + "_";

    if (ciphertext.find(prefix) == 0) {
        return ciphertext.substr(prefix.length());
    }
    else {
        cerr << "[ERROR] Wrong key or corrupted ciphertext!" << endl;
        return "";
    }
}
