#include "authentication_server.h"
#include "encryption.h"
#include <iostream>

AuthenticationServer::AuthenticationServer() {
    // Giả lập database người dùng (username -> password)
    userDB["alice"] = "password123";
}

bool AuthenticationServer::AuthenticateUser(const string& username, const string& password) {
    cout << "[INFO - AS] Server is authenticating ... " << endl;
    if (userDB.find(username) != userDB.end() && userDB[username] == password) {
        cout << "[INFO - AS] User exists." << endl;
        return 1;
    }
    cerr << "[INFO - AS] User does not exist." << endl;
    return 0;
}

string AuthenticationServer::Generate_TGT(const string& username, const vector<unsigned char>& kdc_master_key) {
    string sessionKey = "session_key_" + username;
    cout << "[INFO - AS] Session key (Authen): " << sessionKey << endl;
    return Encryption::Encrypt(sessionKey, kdc_master_key);
}