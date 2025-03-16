#include "ticket_granting_server.h"
#include <iostream>
#include <vector>
#include <sstream>
#include <ctime>  // 🔹 Fix lỗi thiếu thư viện time_t

using namespace std;

vector<unsigned char> stringToVector(const string& str) {
    return vector<unsigned char>(str.begin(), str.end());
}

bool TicketGrantingServer::Validate_TGT(const string& encryptedTGT, const string& kdc_master_key) {
    vector<unsigned char> keyVector = stringToVector(kdc_master_key);
    string decrypted_TGT = Encryption::Decrypt(encryptedTGT, keyVector);

    cout << "[INFO - TGS] Checking TGT... " << endl;

    // 1️⃣ Kiểm tra định dạng TGT
    string username, sessionKey, expirationTime;
    stringstream ss(decrypted_TGT);

    if (!(getline(ss, username, '|') && getline(ss, sessionKey, '|') && getline(ss, expirationTime, '|'))) {
        cerr << "[ERROR - TGS] Invalid TGT format!" << endl;
        return false;
    }

    // 2️⃣ Kiểm tra username có tồn tại trong database không
    string query = "SELECT username FROM users WHERE username = '" + username + "';";
    auto result = db.executeSelectQuery(query);

    if (result.empty()) {  // 🔹 Sửa lỗi: Dùng executeSelectQuery() để kiểm tra kết quả
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

    cout << "[INFO - TGS] Valid TGT!" << endl;
    return true;
}

// 🔹 Thay thế RAND_bytes() bằng random_device để tạo session key an toàn
string generateRandomSessionKey() {
    unsigned char key[32]; // 256-bit key
    RAND_bytes(key, sizeof(key));

    string sessionKey;
    for (int i = 0; i < 32; i++) {
        sessionKey += to_string(key[i] % 10); // Convert to a readable format
    }
    return sessionKey;
}

string TicketGrantingServer::Generate_Service_Ticket(const string& username, const string& serviceName) {
    string sessionKey = generateRandomSessionKey();
    time_t expiration = time(nullptr) + 3600; // Hết hạn sau 1 giờ

    // 🔍 1️⃣ Truy vấn Service Secret Key từ database
    string query = "SELECT service_key FROM services WHERE service_name = '" + serviceName + "';";
    auto result = db.executeSelectQuery(query);

    if (result.empty()) {  // 🔹 Sửa lỗi: Dùng executeSelectQuery() thay vì executeQuery()
        cerr << "[ERROR - TGS] Failed to get Service Secret Key from database!" << endl;
        return "";
    }

    string serviceSecretKey = result[0]["service_key"];

    // 🛠 2️⃣ Tạo Service Ticket (ST)
    string serviceTicketData = username + "|" + sessionKey + "|" + serviceName + "|" + to_string(expiration);
    vector<unsigned char> keyVector = stringToVector(serviceSecretKey);
    string encryptedServiceTicket = Encryption::Encrypt(serviceTicketData, keyVector);

    // 📝 3️⃣ Lưu vào database
    LogServiceTicketToDB(username, serviceName, encryptedServiceTicket, sessionKey, expiration);

    return encryptedServiceTicket;
}

void TicketGrantingServer::LogServiceTicketToDB(const string& username, const string& serviceName, const string& encryptedTicket, const string& sessionKey, time_t expiration) {
    string query = "INSERT INTO service_tickets (username, ticket_data, session_key, issued_at, expires_at) VALUES ('"
        + username + "', '" + encryptedTicket + "', '" + sessionKey + "', NOW(), FROM_UNIXTIME(" + to_string(expiration) + "));";

    if (db.executeNonQuery(query)) {  // 🔹 Sửa lỗi: executeQuery() -> executeNonQuery()
        cout << "[LOG - TGS] Service Ticket saved to DB!\n";
    }
    else {
        cout << "[ERROR - TGS] Failed to save Service Ticket to DB.\n";
    }
}
