#include "service_server.h"
#include "encryption.h"
#include <iostream>
#include <sstream>
#include <ctime>
#include <iomanip>

ServiceServer::ServiceServer(Database & database) : db(database) {
    string query = "SELECT service_name FROM services";
    auto results = db.executeSelectQuery(query);

    for (const auto& row : results) {
        services.push_back(row.at("service_name"));
    }
}

bool ServiceServer::Validate_Service_Ticket(const string& encrypted_ST, const string& encrypted_authenticator, const string& service_name) {
    cout << "------------------- Validate ST -------------------" << endl;
    // Lấy service key
    string query = "SELECT service_key FROM services WHERE service_name = '" + service_name + "';";
    auto result = db.executeSelectQuery(query);

    if (result.empty()) {  // 🔹 Sửa lỗi: Dùng executeSelectQuery() thay vì executeQuery()
        cerr << "[ERROR - SS] Failed to get Service Secret Key from database!" << endl;
        cout << "---------------------------------------------------" << endl;
        return 0;
    }

    string serviceSecretKey = result[0]["service_key"];

    // Decrypt Service Ticket
    vector<unsigned char> ServiceKeyVector(serviceSecretKey.begin(), serviceSecretKey.end());
    string decrypt_ST = Encryption::Decrypt(encrypted_ST, ServiceKeyVector);
    stringstream ss2(decrypt_ST);
    string username_ticket, SK2, service_name_ticket, expiration_time_str;

    getline(ss2, username_ticket, '|');
    getline(ss2, SK2, '|');
    getline(ss2, service_name_ticket, '|');
    getline(ss2, expiration_time_str, '|');

    // 🔐 Decrypt Authenticator bằng sessionKey
    vector<unsigned char> sk2_vector(SK2.begin(), SK2.end());
    string decrypted_authenticator = Encryption::Decrypt(encrypted_authenticator, sk2_vector);
    cout << "[INFO - SS] Decrypted Authenticator: " << decrypted_authenticator << endl;

    // ➕ Parse Authenticator
    string username_auth, timestamp_str;
    stringstream ss_auth(decrypted_authenticator);
    if (!(getline(ss_auth, username_auth, '|') && getline(ss_auth, timestamp_str, '|'))) {
        cerr << "[ERROR - SS] Invalid Authenticator format!" << endl;
        cout << "---------------------------------------------------" << endl;
        return false;
    }

    
    cout << "[INFO - SS] Server is checking ticket... " << endl;

    // ✅ So khớp username
    if (username_auth != username_ticket) {
        cerr << "[ERROR - SS] Authenticator username does not match TGT!" << endl;
        cout << "---------------------------------------------------" << endl;
        return false;
    }

    // 2️⃣ Kiểm tra username có tồn tại trong database không
    query = "SELECT username FROM users WHERE username = '" + username_ticket + "';";
    result = db.executeSelectQuery(query);

    if (result.empty()) {
        cerr << "[ERROR - SS] Username not found in database!" << endl;
        cout << "---------------------------------------------------" << endl;
        return false;
    }

    // Check exp time
    time_t expiration_time = stoll(expiration_time_str);
    time_t current_time = time(nullptr);

    if (current_time > expiration_time) {
        cout << "[ERROR - SS] Service Ticket has expired!" << endl;
        cout << "---------------------------------------------------" << endl;
        return false;
    }

    // Check existance of service
    if (find(services.begin(), services.end(), service_name) == services.end()) {
        cout << "[ERROR - SS] Service does not exists!" << endl;
        cout << "---------------------------------------------------" << endl;
        return false;
    }

    // Check matching service 
    if (service_name_ticket != service_name) {
        cout << "[ERROR - SS] Services do not match!" << endl;
        cout << "---------------------------------------------------" << endl;
        return false;
    }

    cout << "[INFO - SS] Service Ticket is valid for user: " << username_ticket << " accessing: " << service_name << endl;
    cout << "---------------------------------------------------" << endl;
    return true;
}

bool ServiceServer::Grant_Access(string& userName, const string& service_name) {
    cout << "------------------- Grant Access -------------------" << endl;
    // Kiểm tra quyền truy cập
    string query = "SELECT COUNT(*) FROM service_tickets WHERE username = '" + userName +"' AND service_name = '" + service_name + "' AND expires_at > NOW();";
    auto result = db.executeSelectQuery(query);

    // Lấy thời gian hiện tại (access_time)
    time_t now = time(0);
    tm timeinfo;
    localtime_s(&timeinfo, &now);
    stringstream access_time;
    access_time << put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");

    if (result.empty() || result[0]["COUNT(*)"] == "0") {
        cerr << "[ERROR - SS] Access Denied: No valid Service Ticket!" << endl;

        // Lưu vào logs với trạng thái thất bại
        string log_query = "INSERT INTO logs (username, service_name, access_time, status) VALUES ('" + userName + "', '" + service_name + "', '" + access_time.str() + "', 'Failed');";
        db.executeQuery(log_query);

        return 0;
    }

    cout << "[INFO - SS] Access Granted to " << service_name << endl;

    // Lưu lịch sử truy cập thành công vào bảng logs
    string log_query = "INSERT INTO logs (username, service_name, access_time, status) VALUES ('" + userName + "', '" + service_name + "', '" + access_time.str() + "', 'Success');";
    db.executeQuery(log_query);
    cout << "----------------------------------------------------" << endl;
    return 1;
}

bool ServiceServer::Add_Service(const string& service_name, const string& service_key) {
    string query = "INSERT INTO services (service_name, service_key) VALUES ('" + service_name + "', '" + service_key + "')";
    if (db.executeQuery(query)) {
        services.push_back(service_name);
        return true;
    }
    return false;
}

bool ServiceServer::Remove_Service(const string& service_name) {
    string query = "DELETE FROM services WHERE service_name = '" + service_name + "'";
    if (db.executeQuery(query)) {
        services.erase(remove(services.begin(), services.end(), service_name), services.end());
        return true;
    }
    return false;
}