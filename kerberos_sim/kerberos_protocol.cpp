#include "kerberos_protocol.h"
#include "encryption.h"
#include <iostream>

KerberosProtocol::KerberosProtocol(AuthenticationServer& as, TicketGrantingServer& tgs,
    ServiceServer& ss, Database& database)
    : AS(as), TGS(tgs), SS(ss), db(database) {
}

// Gửi yêu cầu xác thực và nhận TGT
string KerberosProtocol::authenticateClient(Client& user) {
    // First authenticate the user credentials
    if (!AS.AuthenticateUser(user.getUserName(), user.getPassword())) {
        return "[ERROR] Authentication failed: Invalid credentials";
    }

    // Generate TGT for the authenticated user
    string encr_TGT = AS.Generate_TGT(user.getUserName(), "master_key_of_quang_duy");

    if (encr_TGT.empty()) {
        return "[ERROR] Failed to generate TGT";
    }

    // Store TGT in client
    user.setTGT(encr_TGT);

    return encr_TGT;
}

// Yêu cầu Service Ticket từ TGS để nhận Service ticket
string KerberosProtocol::requestServiceTicket(Client& user, const string& encrypted_tgt, const string& service_name) {
    // Validate the TGT
    if (!TGS.Validate_TGT(encrypted_tgt, "master_key_of_quang_duy")) {
        return "[ERROR] Invalid TGT";
    }

    // Generate service ticket
    string encr_ST = TGS.Generate_Service_Ticket(user.getUserName(), service_name);

    if (encr_ST.empty()) {
        return "[ERROR] Failed to generate service ticket";
    }

    // Store service ticket in client
    user.setServiceTicket(encr_ST);

    return encr_ST;
}

// Truy cập dịch vụ bằng Service Ticket
bool KerberosProtocol::accessService(Client& user, const string& encrypted_service_ticket, const string& service_name) {
    // Validate the service ticket
    if (!SS.Validate_Service_Ticket(encrypted_service_ticket, "master_key_of_quang_duy")) {
        cout << "[ERROR - KERBEROS] Invalid service ticket" << endl;
        return false;
    }

    // Access the service
    string granting_res = SS.Grant_Access(service_name);
    if (granting_res.find("Access Granted") != string::npos) {
        // Log successful access to database
        string query = "INSERT INTO logs (username, status) VALUES ('" +
            user.getUserName() + "', 'Success');";
        db.executeQuery(query);
        return true;
    }

    // Log failed access attempt
    string query = "INSERT INTO logs (username, status) VALUES ('" +
        user.getUserName() + "', 'Failed');";
    db.executeQuery(query);
    return false;
}