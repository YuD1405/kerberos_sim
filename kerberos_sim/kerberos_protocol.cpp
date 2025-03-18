#include "kerberos_protocol.h"
#include "encryption.h"
#include <iostream>

KerberosProtocol::KerberosProtocol(AuthenticationServer& as, TicketGrantingServer& tgs,
    ServiceServer& ss, Database& database)
    : AS(as), TGS(tgs), SS(ss), db(database) {
}

// Gửi yêu cầu xác thực và nhận TGT
string KerberosProtocol::authenticateClient(Client& user) {
    // Generate TGT for the authenticated user
    string encr_TGT = user.Request_TGT(AS);

    // return to User
    if (encr_TGT.empty()) {
        return "";
    }

    // Store TGT in client
    user.setTGT(encr_TGT);

    // Store ssk_1 in client


    return encr_TGT;
}

// Yêu cầu Service Ticket từ TGS để nhận Service ticket
string KerberosProtocol::requestServiceTicket(Client& user, const string& encrypted_tgt, const string& service_name) {
    // Generate service ticket
    string encr_ST = user.UserRequest_ServiceTicket(TGS, encrypted_tgt, service_name);

    if (encr_ST.empty()) {
        return "";
    }

    // Store service ticket in client
    user.setServiceTicket(encr_ST);

    // Store ssk_2 in client


    return encr_ST;
}

// Truy cập dịch vụ bằng Service Ticket
bool KerberosProtocol::accessService(Client& user, const string& encrypted_service_ticket, const string& service_name) {
    string granting_res = user.Access_Service(SS, encrypted_service_ticket, service_name);

    // Log failed access attempt
    if (granting_res.empty()) {
        string query = "INSERT INTO logs (username, status) VALUES ('" +
            user.getUserName() + "', 'Failed');";
        db.executeQuery(query);
        return false;
    }
    return true;
}