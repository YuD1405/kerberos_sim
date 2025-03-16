#include "service_server.h"
#include "encryption.h"
#include <iostream>
#include <sstream>

ServiceServer::ServiceServer(Database& database): db(database){
    std::string query = "SELECT service_name FROM services";
    auto results = db.executeSelectQuery(query);

    for (const auto& row : results) {
        services.push_back(row.at("service_name"));
    }
}

bool ServiceServer::Validate_Service_Ticket(string& userName, const string& encrypted_ST, const string& encrypted_authenticator, const string& service_name) {
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

    // Decrypt authenticator
    vector<unsigned char> SK2Vector(SK2.begin(), SK2.end());
    string decrypt_authenticator = Encryption::Decrypt(encrypted_authenticator, SK2Vector);
    stringstream ss1(decrypt_authenticator);
    string username_authen;
    getline(ss1, username_authen, '|');

    cout << "[INFO - ST] Server is checking ticket... " << endl;
    
    // Check valid user name
    // Check username in ST và Authenticator
    if (username_ticket != username_authen) {
        cout << "[ERROR - ST] Username mismatch between ST and Authenticator!" << endl;
        return false;
    }

    // Check username trong client và Authenticator
    if (userName != "" && userName != username_authen) {
        cout << "[WARNING - ST] Client username does not match Authenticator username!" << endl;
        return false;
    }

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

string ServiceServer::Grant_Access(const string& service_name) {
    return "[INFO - ST] Access Granted to " + service_name;
}

bool ServiceServer::Add_Service(const string& service_name, const string& service_key) {
    string query = "INSERT INTO services (service_name, service_key) VALUES ('" + service_name + "', '" + service_key + "')";
    if (db.executeNonQuery(query)) {
        services.push_back(service_name);
        return true;
    }
    return false;
}

bool ServiceServer::Remove_Service(const string& service_name) {
    string query = "DELETE FROM services WHERE service_name = '" + service_name + "'";
    if (db.executeNonQuery(query)) {
        services.erase(remove(services.begin(), services.end(), service_name), services.end());
        return true;
    }
    return false;
}