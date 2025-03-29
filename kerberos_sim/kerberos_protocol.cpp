#include "kerberos_protocol.h"
#include "encryption.h"
#include <iostream>

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
bool KerberosProtocol::phase_2(Client& user, const string& service_name) {
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