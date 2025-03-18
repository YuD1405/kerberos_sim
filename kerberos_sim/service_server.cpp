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

bool ServiceServer::Validate_Service_Ticket(const string& encrypted_ST, const string& service_name) {
    // Lấy service key
    string query = "SELECT service_key FROM services WHERE service_name = '" + service_name + "';";
    auto result = db.executeSelectQuery(query);

    if (result.empty()) {  // 🔹 Sửa lỗi: Dùng executeSelectQuery() thay vì executeQuery()
        cerr << "[ERROR - TGS] Failed to get Service Secret Key from database!" << endl;
        return "";
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

    cout << "[INFO - ST] Server is checking ticket... " << endl;

    // Check exp time
    time_t expiration_time = stoll(expiration_time_str);
    time_t current_time = time(nullptr);

    if (current_time > expiration_time) {
        cout << "[ERROR - ST] Service Ticket has expired!" << endl;
        return false;
    }

    // Check existance of service
    if (find(services.begin(), services.end(), service_name) == services.end()) {
        cout << "[ERROR - ST] Service does not exists!" << endl;
        return false;
    }

    // Check matching service 
    if (service_name_ticket != service_name) {
        cout << "[ERROR - ST] Services do not match!" << endl;
        return false;
    }

    cout << "[INFO] Service Ticket is valid for user: " << username_ticket << " accessing: " << service_name << endl;
    return true;
}

string ServiceServer::Grant_Access(string& userName, const string& service_name) {
    // Kiểm tra quyền truy cập
    string query = "SELECT COUNT(*) FROM service_tickets WHERE username = '" + userName +
        "' AND expires_at > NOW();";
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
        string log_query = "INSERT INTO logs (username, access_time, status) VALUES ('" + userName + "', '" + access_time.str() + "', 'Failed');";
        db.executeQuery(log_query);

        return "[ERROR - SS] Access Denied!";
    }

    cout << "[INFO - SS] Access Granted to " << service_name << endl;

    // Lưu lịch sử truy cập thành công vào bảng logs
    string log_query = "INSERT INTO logs (username, access_time, status) VALUES ('" + userName + "', '" + access_time.str() + "', 'Success');";
    db.executeQuery(log_query);

    return "[INFO - SS] Access Granted to " + service_name;
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