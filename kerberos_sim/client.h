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
    string encrypted_TGT;
    string encrypted_service_ticket;
    string session_key;

public:
    Client(const string& user, const string& pw) : username(user), password(pw) {}
    string Request_TGT(AuthenticationServer& AS);
    string UserRequest_ServiceTicket(TicketGrantingServer& TGS, const string& encrypted_TGT, const string& service_name);
    string Access_Service(ServiceServer& SS, const string& encrypted_service_ticket, const string& sessionkey_2, const string& service_name);
};

#endif // CLIENT_H
