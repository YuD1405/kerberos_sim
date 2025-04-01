#include "ticket_granting_server.h"
#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include "global.h"

vector<unsigned char> stringToVector(const string& str) {
    return vector<unsigned char>(str.begin(), str.end());
}

bool TicketGrantingServer::Validate_TGT(const string& encryptedTGT, const string& encrypted_authenticator) {
    cout << "\n--------------- Validate ---------------" << endl;
    // 🔐 Decrypt TGT
    vector<unsigned char> keyVector = stringToVector(kdc_master_key);
    string decrypted_TGT = Encryption::Decrypt(encryptedTGT, keyVector);
    cout << "[INFO - TGS] Checking TGT... " << endl;
    cout << "--> Decrypted TGT: " << decrypted_TGT << endl;

    // ➕ Parse TGT
    string username_TGT, sessionKey, expirationTime;
    stringstream ss(decrypted_TGT);
    if (!(getline(ss, username_TGT, '|') && getline(ss, sessionKey, '|') && getline(ss, expirationTime, '|'))) {
        cerr << "[ERROR - TGS] Invalid TGT format!" << endl;
        return false;
    }

    // 🔐 Decrypt Authenticator bằng sessionKey
    vector<unsigned char> sk1_vector(sessionKey.begin(), sessionKey.end());
    string decrypted_authenticator = Encryption::Decrypt(encrypted_authenticator, sk1_vector);
    cout << "--> Decrypted Authenticator: " << decrypted_authenticator << endl;

    // ➕ Parse Authenticator
    string username_auth, timestamp_str;
    stringstream ss_auth(decrypted_authenticator);
    if (!(getline(ss_auth, username_auth, '|') && getline(ss_auth, timestamp_str, '|'))) {
        cerr << "[ERROR - TGS] Invalid Authenticator format!" << endl;
        return false;
    }

    // ✅ So khớp username
    if (username_auth != username_TGT) {
        cerr << "[ERROR - TGS] Authenticator username does not match TGT!" << endl;
        return false;
    }

    // 2️⃣ Kiểm tra username có tồn tại trong database không
    string query = "SELECT username FROM users WHERE username = '" + username_TGT + "';";
    auto result = db.executeSelectQuery(query);

    if (result.empty()) {
        cerr << "[ERROR - TGS] Username not found in database!" << endl;
        return false;
    }

    // 3️⃣ Kiểm tra thời gian hết hạn của TGT
    time_t currentTime = time(nullptr);
    time_t tgtExpiration = stoll(expirationTime);

    if (currentTime > tgtExpiration) {
        cerr << "[ERROR - TGS] TGT has expired!" << endl;
        return false;
    }

    cout << "[INFO - TGS] TGT and Authenticator are valid!" << endl;
    cout << "----------------------------------------" << endl;
    return true;
}

string generateRandomSessionKey() {
    vector<unsigned char> randomBytes = Encryption::GenerateRandomKey();

    // Convert to hex string for readability
    return string(randomBytes.begin(), randomBytes.end());
}

string TicketGrantingServer::getEncryptedSK2(const string& encrypted_tgt) {
    vector<unsigned char> keyVector = stringToVector(kdc_master_key);
    string decrypted_TGT = Encryption::Decrypt(encrypted_tgt, keyVector);

    string username_TGT, sessionKey_1, expirationTime;
    stringstream ss(decrypted_TGT);
    getline(ss, username_TGT, '|'); getline(ss, sessionKey_1, '|'); getline(ss, expirationTime, '|');

    string sessionKey_2 = generateRandomSessionKey();
    vector<unsigned char> sk1Vector(sessionKey_1.begin(), sessionKey_1.end());
    string encrypted_SSK2 = Encryption::Encrypt(sessionKey_2, sk1Vector);

    return encrypted_SSK2;
}

pair<string, string> TicketGrantingServer::Generate_sk_Ticket(const string& username, const string& serviceName, const string & encrypted_tgt) {
    cout << "\n--------------- Generate ---------------" << endl;

    // 🔐 Decrypt TGT
    vector<unsigned char> keyVector = stringToVector(kdc_master_key);
    string decrypted_TGT = Encryption::Decrypt(encrypted_tgt, keyVector);

    // ➕ Parse TGT
    string username_TGT, sessionKey_1, expirationTime;
    stringstream ss(decrypted_TGT);
    getline(ss, username_TGT, '|'); getline(ss, sessionKey_1, '|'); getline(ss, expirationTime, '|');
    
    string sessionKey_2 = generateRandomSessionKey();
    time_t expiration = time(nullptr) + 3600; // Hết hạn sau 1 giờ

    //// 🔍 1️⃣ Truy vấn Service Secret Key từ database
    string query = "SELECT service_key FROM services WHERE service_name = '" + serviceName + "';";
    auto result = db.executeSelectQuery(query);

    if (result.empty()) {
        cerr << "[ERROR - TGS] Failed to get Service Secret Key from database!" << endl;
        return { "","" };
    }

    string serviceSecretKey = result[0]["service_key"];

    // 🛠 2️⃣ Tạo Service Ticket (ST)
    string serviceTicketData = username + "|" + sessionKey_2 + "|" + serviceName + "|" + to_string(expiration);
    vector<unsigned char> serviceKeyVector = stringToVector(serviceSecretKey);
    string encryptedServiceTicket = Encryption::Encrypt(serviceTicketData, serviceKeyVector);
    
    // Encrypt ssk2
    vector<unsigned char> sk1Vector(sessionKey_1.begin(), sessionKey_1.end());
    string encrypted_SSK2 = Encryption::Encrypt(sessionKey_2, sk1Vector);

	cout << "--> Session Key 2: " << sessionKey_2 << endl;
	cout << "--> Service Ticket Data: " << serviceTicketData << endl;
	cout << "--> Encrypted Service Ticket: " << encryptedServiceTicket << endl;

    // 📝 3️⃣ Lưu vào database
    LogServiceTicketToDB(username, serviceName, encryptedServiceTicket, encrypted_SSK2, expiration);
    cout << "----------------------------------------" << endl;

    return { encrypted_SSK2, encryptedServiceTicket }; // Trả về cặp sessionKey + ST mã hóa
}

void TicketGrantingServer::LogServiceTicketToDB(const string& username, const string& serviceName, const string& encryptedTicket, const string& sessionKey, time_t expiration) {
    string query = "INSERT INTO service_tickets (username, service_name, ticket_data, session_key, issued_at, expires_at) VALUES ('"
        + username + "', '" + serviceName + "', '" + encryptedTicket + "', '" + sessionKey + "', NOW(), FROM_UNIXTIME(" + to_string(expiration) + "));";

    if (db.executeQuery(query)) {
        cout << "[LOG - TGS] Service Ticket saved to DB for service: " << serviceName << "!\n";
    }
    else {
        cout << "[ERROR - TGS] Failed to save Service Ticket to DB.\n";
    }
}

bool TicketGrantingServer::Revoke_Service_Ticket(const string& serviceTicket) {
    string query = "DELETE FROM service_tickets WHERE ticket_data = '" + serviceTicket + "';";

    if (db.executeQuery(query)) {
        cout << "[INFO - TGS] Service Ticket revoked successfully!\n";
        return true;
    }
    cout << "[ERROR - TGS] Service Ticket not found!\n";
    return false;
}

void TicketGrantingServer::RemoveExpiredTickets() {
    string query = "DELETE FROM service_tickets WHERE expires_at < NOW();";

    if (db.executeQuery(query)) {
        cout << "[INFO - TGS] Expired Service Tickets removed!\n";
    }
    else {
        cout << "[ERROR - TGS] Failed to remove expired tickets.\n";
    }
}

bool TicketGrantingServer::CheckExistST(const string&username, const string& serviceName) {
    string query = "SELECT COUNT(*) FROM service_tickets WHERE username = '" + username +
        "' AND service_name = '" + serviceName + "' AND expires_at > NOW();";
    auto result = db.executeSelectQuery(query);

    if (!result.empty() && stoi(result[0]["COUNT(*)"]) > 0) {
        cout << "[INFO - TGS] Valid Service Ticket exists. No need to issue a new one.\n";
        return 1;
    }
    return 0;
}

pair<string, string> TicketGrantingServer::getServiceTicket(const string& username, const string& serviceName) {
    string query = "SELECT ticket_data, session_key FROM service_tickets "
        "WHERE username = '" + username + "' "
        "AND service_name = '" + serviceName + "' "
        "AND expires_at > NOW();";

    auto result = db.executeSelectQuery(query);

    if (result.empty()) {
        cerr << "[ERROR - DB] No valid service ticket found!" << endl;
        return { "", "" };  // Không tìm thấy ST hợp lệ
    }

    string ticketData = result[0]["ticket_data"];
    string sessionKey = result[0]["session_key"];

    return { ticketData, sessionKey };
}