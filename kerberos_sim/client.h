#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include "authentication_server.h"
#include "ticket_granting_server.h"
#include "service_server.h"

using namespace std;

class Client {
private:
    string username;
    string password;
    pair<string, string> encrypted_return;
    string encrypted_service_ticket;
    string encrypted_tgt;
    string encrypted_session_key_1;
    string encrypted_session_key_2;
    string session_key_1;
    string session_key_2;
    bool existST;

public:
    Client(const string& user, const string& pw) : username(user), password(pw) {}
    bool Request_TGT(AuthenticationServer& AS);
    bool Request_ServiceTicket(TicketGrantingServer& TGS, const string& service_name);
    bool Access_Service(ServiceServer& SS, const string& service_name);
};

#endif // CLIENT_H
