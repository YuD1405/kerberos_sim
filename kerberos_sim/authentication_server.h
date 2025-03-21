#ifndef AUTHENTICATION_SERVER_H
#define AUTHENTICATION_SERVER_H

#include <string>
#include <unordered_map>
#include "database.h"
using namespace std;

class AuthenticationServer {
public:
    AuthenticationServer(Database& database);
    
    // User management functions
    bool AddUser(const string& username, const string& password);
    bool RemoveUser(const string& username);
    bool AuthenticateUser(const string& username, const string& password);
    
    // TGT generation
    pair<string, string> Generate_TGT(const string& username, const string& kdc_master_key, const string& password);

private:
    Database& db;
    
    // Helper methods
    string hashPassword(const string& password);
    string generateRandomSessionKey();
    void LogTGTIssuance(const string& username, const string& sessionKey, time_t expirationTime);
};

#endif