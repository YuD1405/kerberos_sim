#ifndef TICKET_GRANTING_SERVER_H
#define TICKET_GRANTING_SERVER_H

#include <string>
#include <ctime>
#include "database.h"
#include "encryption.h"

using namespace std;

class TicketGrantingServer {
private:
    Database& db;

public:
    TicketGrantingServer(Database& database) : db(database) {}

    bool Validate_TGT(const string& encryptedTGT, const string& encrypted_authenticator);
    pair<string, string> Generate_sk_Ticket(const string& username, const string& serviceName, const string& encrypted_tgt);
    void LogServiceTicketToDB(const string& username, const string& serviceName, const string& encryptedTicket, const string& sessionKey, time_t expiration);
    bool Revoke_Service_Ticket(const string& serviceTicket);
    void RemoveExpiredTickets();
};

#endif
