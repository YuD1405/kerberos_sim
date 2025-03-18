#include "client.h"
#include "global.h"

// Getter methods
string Client::getUserName() {
    return username;
}

string Client::getPassword() {
    return password;
}

string Client::getServiceTicket() {
    return encrypted_service_ticket;
}

string Client::getTGT() {
    return encrypted_TGT;
}

string Client::getSessionKey_1() {
    return session_key_1;
}

string Client::getSessionKey_2() {
    return session_key_2;
}

// Setter methods
void Client::setSessionKey_1(string session_key) {
    this->session_key_1 = session_key;
}

void Client::setSessionKey_2(string session_key) {
    this->session_key_2 = session_key;
}

void Client::setServiceTicket(string ticket) {
    this->encrypted_service_ticket = ticket;
}

void Client::setTGT(string ticket) {
    this->encrypted_TGT = ticket;
}

string Client::Request_TGT(AuthenticationServer& AS) {
    cout << "[REQUEST - CLIENT] Sending authentication request for user " << username << "...\n";
    if (!AS.AuthenticateUser(username, password)) {
        cerr << "[ERROR - CLIENT] Authentication failed.\n";
        return "";
    }

    // Generate TGT for the authenticated user
    encrypted_TGT = AS.Generate_TGT(username, kdc_master_key);

    // Generate session key 1


    if (!encrypted_TGT.empty()) {
        cout << "[INFO - CLIENT] Received TGT. Authentication successful!\n";
        return encrypted_TGT;
    }
    else {
        cerr << "[ERROR - CLIENT] Generate ticket failed.\n";
        return "";
    }
}

string Client::UserRequest_ServiceTicket(TicketGrantingServer& TGS, const string& encrypted_TGT, const string& service_name) {
    // Decr sk1 by pw 

    // Create authenticator

    // Encr by sk1

    // Request
    cout << "[REQUEST - CLIENT] Sending service request for user " << username << "...\n";
    if (!TGS.Validate_TGT(encrypted_TGT, kdc_master_key)) {
        cerr << "[ERROR - CLIENT] Validate ticket failed.\n";
        return "";
    }

    // Generate ST
    pair<string, string> gen_return = TGS.Generate_Service_Ticket(username, service_name);
    encrypted_service_ticket = gen_return.second;

    // Generate ssk2
    session_key_2 = gen_return.first;

    if (!encrypted_service_ticket.empty() || !session_key_2.empty()) {
        cout << "[INFO - CLIENT] Client: Received Service Ticket !\n";
        return encrypted_service_ticket;
    }
    else {
        cerr << "[ERROR - CLIENT] Client: Received ST / session key failed.\n";
        return "";
    }
}

string Client::Access_Service(ServiceServer& SS, const string& service_ticket, const string& service_name) {
    cout << "[ACCESS - CLIENT] Access to service: " << service_name << "...\n";
    if (!SS.Validate_Service_Ticket(service_ticket, service_name)) {
        cerr << "[ERROR - CLIENT] Validate service ticket failed.\n";
        return "";
    }

    string granting_result = SS.Grant_Access(username ,service_name);
    cout << "[ACCESS - CLIENT] Accessible for " + service_name << endl;
    return granting_result;
}