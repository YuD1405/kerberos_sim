#include "kerberos_protocol.h"
#include "encryption.h"
#include <iostream>

vector<string> loadServices(Database& db) {
    vector<string> services;
    string query = "SELECT service_name FROM services;";
    auto result = db.executeSelectQuery(query);

    if (result.empty()) {
        cerr << "[ERROR - SS] No services found in database!" << endl;
        return services;
    }

    for (const auto& row : result) {
        if (row.find("service_name") != row.end()) {
            services.push_back(row.at("service_name"));
        }
    }

    return services;
}

KerberosProtocol::KerberosProtocol(AuthenticationServer& as, TicketGrantingServer& tgs,
    ServiceServer& ss, Database& database)
    : AS(as), TGS(tgs), SS(ss), db(database) {
}

// Gửi yêu cầu xác thực và nhận TGT
bool KerberosProtocol::phase_1(Client& user) {
    // Generate TGT for the authenticated user
    bool phase_1_res = user.Request_TGT(AS);

    if (!phase_1_res) {
        cout << "[ERROR - KBR] Phase 1 failed" << endl;
        return 0;
    }

    cout << "[INFO - KBR] Phase 1 completed" << endl;
    return 1;
}

// Yêu cầu Service Ticket từ TGS để nhận Service ticket
bool KerberosProtocol::phase_2(Client& user, string& service_name) {
    // Select service    
    vector<string> serviceList = loadServices(db);

    cout << "Available service:" << endl;
    for (int i = 0; i < serviceList.size(); i++) {
        cout << i + 1 << ". " << serviceList[i] << endl;
    }

    int choice;
    cout << endl << "Choose Service: "; cin >> choice;
    service_name = serviceList[choice - 1];

    // Generate service ticket
    bool phase_2_res = user.Request_ServiceTicket(TGS, service_name);

    if (!phase_2_res) {
        cout << "[ERROR - KBR] Phase 2 failed" << endl;
        return 0;
    }
    cout << "[INFO - KBR] Phase 2 completed" << endl;
    return 1;
}

// Truy cập dịch vụ bằng Service Ticket
bool KerberosProtocol::phase_3(Client& user, const string& service_name) {
    bool phase_3_res = user.Access_Service(SS, service_name);
    
    if (!phase_3_res) {
        cout << "[ERROR - KBR] Phase 3 failed" << endl;
        return 0;
    }
    cout << "[INFO - KBR] Phase 3 completed" << endl;
    return 1;
}