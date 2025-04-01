#include "authentication_server.h"
#include "encryption.h"
#include <iostream>
#include <ctime>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include "global.h"

// Hash password using SHA-256
string AuthenticationServer::hashPassword(const string& password) {
    // Create a new EVP_MD_CTX for the hash operation
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        cerr << "[ERROR - AS] Failed to create hash context" << endl;
        return "";
    }

    // Initialize the hash context with SHA-256
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        cerr << "[ERROR - AS] Failed to initialize hash algorithm" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Update the hash with the password data
    if (1 != EVP_DigestUpdate(mdctx, password.c_str(), password.length())) {
        cerr << "[ERROR - AS] Failed to update hash" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Finalize the hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        cerr << "[ERROR - AS] Failed to finalize hash" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Clean up the context
    EVP_MD_CTX_free(mdctx);

    // Convert the hash to a hex string
    stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

AuthenticationServer::AuthenticationServer(Database& database) : db(database) {
    //cout << "[INFO - AS] Authentication Server initialized\n";
}

bool AuthenticationServer::AddUser(const string& username, const string& password) {
    cout << "[INFO - AS] Adding user: " << username << endl;

    // First check if user already exists
    string checkQuery = "SELECT COUNT(*) AS CNT FROM users WHERE username = '" + username + "';";
    auto res = db.executeSelectQuery(checkQuery);
    string count = res[0]["CNT"];
    if (count != "0") {
        cout << "[INFO - AS] User " << username << " already exists\n";
        return false;
    }

    // Hash the password before storing
    string hashedPassword = hashPassword(password);

    // Create SQL query to insert user
    string query = "INSERT INTO users (username, password_hash) VALUES ('" +
        username + "', '" + hashedPassword + "');";

    if (db.executeQuery(query)) {
        cout << "[INFO - AS] User " << username << " added successfully\n";
        return true;
    }
    else {
        cerr << "[ERROR - AS] Failed to add user " << username << endl;
        return false;
    }
}

bool AuthenticationServer::RemoveUser(const string& username) {
    cout << "[INFO - AS] Removing user: " << username << endl;
    
    string query = "DELETE FROM users WHERE username = '" + username + "';";
    
    if (db.executeQuery(query)) {
        cout << "[INFO - AS] User " << username << " removed successfully\n";
        return true;
    } else {
        cerr << "[ERROR - AS] Failed to remove user " << username << endl;
        return false;
    }
}

bool AuthenticationServer::AuthenticateUser(const string& username, const string& password) {
    cout << "\n--------------- Authenticate ---------------" << endl;
    cout << "[INFO - AS] Authenticating user: " << username << "..." << endl;
    
    // Hash the provided password
    string hashedPassword = hashPassword(password);
    
    // Query to check if user exists with matching password
    string query = "SELECT username FROM users WHERE username = '" + 
                   username + "' AND password_hash = '" + hashedPassword + "';";
    
    //// Create a flag to track authentication result
    bool authResult = false;
    
    try {
        // Execute query and check if there's a match
        std::unique_ptr<sql::Statement> stmt(db.getConnection()->createStatement());
        std::unique_ptr<sql::ResultSet> res(stmt->executeQuery(query));
        
        if (res->next()) {
            cout << "[INFO - AS] User authenticated successfully\n";
            authResult = true;
        } else {
            cerr << "[INFO - AS] User does not exist or Wrong Password." << endl;
        }
    } catch (sql::SQLException& e) {
        cerr << "[ERROR - AS] SQL error during authentication: " << e.what() << endl;
    }
    cout << "--------------------------------------------\n" << endl;
    return authResult;
}

pair<string, string> AuthenticationServer::Generate_sk_ticket(const string& username, const string& password) {
    cout << "\n--------------- Gernerate Ticket ---------------" << endl;
    // Generate a random session key
    string sessionKey = generateRandomSessionKey();
    //cout << "[INFO - AS] Generated session key for " << username << endl;
	cout << "--> Session key TGT: " << sessionKey << endl;
    // Set expiration time (e.g., 8 hours from now)
    time_t expirationTime = time(nullptr) + 8 * 3600;
    
    // Create TGT content (username | session key | expiration time)
    string tgtContent = username + "|" + sessionKey + "|" + to_string(expirationTime);
	cout << "--> TGT Content: " << tgtContent << endl;

    // Convert master key to vector for encryption
    vector<unsigned char> keyVector(kdc_master_key.begin(), kdc_master_key.end());
    
    // Encrypt TGT
    string encryptedTGT = Encryption::Encrypt(tgtContent, keyVector);
	cout << "--> Encrypted TGT: " << encryptedTGT << endl;
    
    // Encrypt SS1
    vector<unsigned char> password_vector(password.begin(), password.end());
    string SSK1_encrypt = Encryption::Encrypt(sessionKey, password_vector);

    // Log TGT issuance to database
    //LogTGTIssuance(username, sessionKey, expirationTime);
    
    cout << "------------------------------------------------\n" << endl;
    return { SSK1_encrypt ,encryptedTGT };
}

string AuthenticationServer::generateRandomSessionKey() {
    // Generate a cryptographically secure random session key
    vector<unsigned char> randomBytes = Encryption::GenerateRandomKey();
    
    // Convert to hex string for readability
    return string(randomBytes.begin(), randomBytes.end());
}

//void AuthenticationServer::LogTGTIssuance(const string& username, const string& sessionKey, time_t expirationTime) {
//    // Create a table for TGT tracking if it doesn't exist
//    string createTableQuery = 
//        "CREATE TABLE IF NOT EXISTS tgt_logs ("
//        "id INT PRIMARY KEY AUTO_INCREMENT, "
//        "username VARCHAR(255) NOT NULL, "
//        "session_key VARCHAR(255) NOT NULL, "
//        "issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
//        "expires_at TIMESTAMP NOT NULL, "
//        "FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE"
//        ");";
//    
//    db.executeQuery(createTableQuery);
//    
//    // Insert TGT issuance record
//    string query = "INSERT INTO tgt_logs (username, session_key, expires_at) VALUES ('" +
//                   username + "', '" + sessionKey + "', FROM_UNIXTIME(" + 
//                   to_string(expirationTime) + "));";
//    
//    if (db.executeQuery(query)) {
//        cout << "[INFO - AS] TGT issuance logged successfully\n";
//    } else {
//        cerr << "[ERROR - AS] Failed to log TGT issuance\n";
//    }
//}