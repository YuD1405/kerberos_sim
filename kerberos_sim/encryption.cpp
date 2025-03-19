#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <cstring>

vector<unsigned char> Encryption::GenerateRandomKey() {
    const string hex_chars = "0123456789ABCDEF";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> distrib(0, 15); // Chỉ lấy giá trị từ 0 đến 15 (tương ứng với 0-F)

    vector<unsigned char> key(32);
    for (int i = 0; i < 32; i++) {
        key[i] = hex_chars[distrib(gen)]; // Lấy ngẫu nhiên 1 ký tự từ hex_chars
    }

    return key;
}

string Encryption::Encrypt(const string& plaintext, const vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "[ERROR] Không thể tạo context mã hóa!" << endl;
        return "";
    }

    // Khởi tạo mã hóa AES-256-ECB (không cần IV)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr) != 1) {
        cerr << "[ERROR] Lỗi khi khởi tạo mã hóa!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_ecb()));
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        cerr << "[ERROR] Lỗi khi mã hóa dữ liệu!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        cerr << "[ERROR] Lỗi khi hoàn tất mã hóa!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

string Encryption::Decrypt(const string& ciphertext, const vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "[ERROR] Không thể tạo context giải mã!" << endl;
        return "";
    }

    // Khởi tạo AES-256-ECB (không cần IV)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr) != 1) {
        cerr << "[ERROR] Lỗi khi khởi tạo giải mã!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
        cerr << "[ERROR] Lỗi khi giải mã dữ liệu!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        cerr << "[ERROR] Lỗi khi hoàn tất giải mã!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string(plaintext.begin(), plaintext.begin() + plaintext_len);
}