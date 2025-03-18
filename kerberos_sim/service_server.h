#ifndef SERVICE_SERVER_H
#define SERVICE_SERVER_H

#include <string>
#include <vector>
#include "database.h" 
using namespace std;

class ServiceServer {
private:
    vector<string> services;
    Database& db;

public:
    ServiceServer(Database& database);
    bool Validate_Service_Ticket(const string& encrypted_ST, const string& service_name);
    string Grant_Access(string& userName, const string& service_name);
    bool Add_Service(const string& service_name, const string& service_key);
    bool Remove_Service(const string& service_name);
};

#endif