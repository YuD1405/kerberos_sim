#include <iostream>
#include "client.h"
#include <ctime>

string Client::Request_TGT(AuthenticationServer& AS) {
    cout << "[REQUEST - CLIENT] Sending authentication request for user " << username << "...\n";
    if (!AS.AuthenticateUser(username, password)) {
        return "Failed: User does not exists.";
    }

    vector<unsigned char> masterKeyVector(
        "master_key_of_quang_duy",
        "master_key_of_quang_duy" + sizeof("master_key_of_quang_duy") - 1
    );
    encrypted_TGT = AS.Generate_TGT(username, masterKeyVector);

    if (!encrypted_TGT.empty()) {
        cout << "[INFO - CLIENT] Received TGT. Authentication successful!\n";
        return encrypted_TGT;
    }
    else {
        cerr << "[ERROR - CLIENT] Authentication failed.\n";
        return "Failed: Generate TGT failed.";
    }
}

string Client::UserRequest_ServiceTicket(TicketGrantingServer& TGS, const string& encrypted_TGT, const string& service_name) {
    cout << "[REQUEST - CLIENT] Sending service request for user " << username << "...\n";
    if (!TGS.Validate_TGT(encrypted_TGT, "master_key_of_quang_duy")) {
        return "Failed: Invalid TGT";
    }

    encrypted_service_ticket = TGS.Generate_Service_Ticket(service_name, "master_key_of_quang_duy");

    if (!encrypted_service_ticket.empty()) {
        cout << "[INFO - CLIENT] Client: Received Service Ticket !\n";
        return encrypted_service_ticket;
    }
    else {
        cerr << "[ERROR - CLIENT] Client: Generate ST failed.\n";
        return "Failed: Generate ST failed.";
    }
}

string Client::Access_Service(ServiceServer& SS, const string& encrypted_service_ticket, const string& sessionkey_2, const string& service_name) {
    time_t now = time(nullptr);
    string timestamp = std::to_string(now);
    string authenticator = username + "|" + timestamp;
    vector<unsigned char> SK2Vector(sessionkey_2.begin(), sessionkey_2.end());
    string encrypted_authenticator = Encryption::Encrypt(authenticator, SK2Vector);

    cout << "[ACCESS - CLIENT] Access to service: " << service_name << "...\n";
    if (!SS.Validate_Service_Ticket(username, encrypted_service_ticket, encrypted_authenticator, service_name)) {
        return "Failed: Invalid Service ticket";
    }

    string granting_result = SS.Grant_Access(service_name);
    cout << "[ACCESS - CLIENT] Accessible for " + service_name << endl;
    return granting_result;
    return "";
}