//#include <iostream>
//#include "kerberos_protocol.h"
//#include "authentication_server.h"
//#include "ticket_granting_server.h"
//#include "service_server.h"
//#include "database.h"
//#include "client.h"
//
//int main() {
//    // 1. Initialize database connection
//    Database db("127.0.0.1", "root", "captyuddy1405", "kerberos_db");
//    if (!db.connect()) {
//        cerr << "[ERROR - MAIN] Failed to connect to database" << endl;
//        return 1;
//    }
//    cout << "[INFO - MAIN] Successfully connected to database" << endl;
//
//    // 2. Initialize servers
//    AuthenticationServer AS(db);
//    TicketGrantingServer TGS(db);
//    ServiceServer SS;
//
//    // 3. Set up the Kerberos protocol
//    KerberosProtocol kerberos(AS, TGS, SS, db);
//
//    // 4. KDC master key (in a real system, this would be securely stored)
//    string kdc_master_key = "master_key_of_quang_duy";
//
//    // 5. Demonstrate user management
//    cout << "\n========== User Management Demonstration ==========\n";
//
//    // Add a new user
//    string newUsername = "bob";
//    string newPassword = "securepass123";
//    if (AS.AddUser(newUsername, newPassword)) {
//        cout << "[INFO - MAIN] User " << newUsername << " added successfully" << endl;
//    }
//
//    // Test authentication with the new user
//    if (AS.AuthenticateUser(newUsername, newPassword)) {
//        cout << "[INFO - MAIN] Authentication successful for " << newUsername << endl;
//    }
//    else {
//        cout << "[ERROR - MAIN] Authentication failed for " << newUsername << endl;
//    }
//
//    // 6. Create a client for the new user
//    Client client(newUsername, newPassword);
//
//    // 7. Full Kerberos authentication flow
//    cout << "\n========== Full Kerberos Authentication Flow ==========\n";
//
//    // Step 1: Authenticate with AS and get TGT
//    cout << "---- Step 1: Authenticating with Authentication Server ----\n";
//    string encryptedTGT = kerberos.authenticateClient(client);
//    if (encryptedTGT.find("[ERROR]") != string::npos) {
//        cout << "[ERROR - MAIN] Authentication failed" << endl;
//        return 1;
//    }
//    cout << "[INFO - MAIN] Authentication successful, received TGT" << endl;
//    cout << encryptedTGT << endl;
//    // Step 2: Request service ticket from TGS
//    //cout << "\n---- Step 2: Requesting Service Ticket from TGS ----\n";
//    //string serviceName = "FileServer";
//    //string encryptedServiceTicket = kerberos.requestServiceTicket(client, encryptedTGT, serviceName);
//    //if (encryptedServiceTicket.find("[ERROR]") != string::npos) {
//    //    cout << "[ERROR - MAIN] Failed to obtain service ticket" << endl;
//    //    return 1;
//    //}
//    //cout << "[INFO - MAIN] Successfully obtained service ticket for " << serviceName << endl;
//
//    //// Step 3: Access the service
//    //cout << "\n---- Step 3: Accessing Service with Service Ticket ----\n";
//    //if (kerberos.accessService(client, encryptedServiceTicket, serviceName)) {
//    //    cout << "[INFO - MAIN] Successfully accessed " << serviceName << endl;
//    //}
//    //else {
//    //    cout << "[ERROR - MAIN] Failed to access " << serviceName << endl;
//    //    return 1;
//    //}
//
//    // 8. Optional: Clean up (remove test user)
//    cout << "\n========== Cleanup ==========\n";
//    if (AS.RemoveUser(newUsername)) {
//        cout << "[INFO - MAIN] User " << newUsername << " removed successfully" << endl;
//    }
//
//    cout << "\n[INFO - MAIN] Kerberos demonstration completed successfully" << endl;
//    return 0;
//}

#include <iostream>
#include "kerberos_protocol.h"
#include "authentication_server.h"
#include "ticket_granting_server.h"
#include "service_server.h"
#include "database.h"
#include "client.h"
#include "global.h"

string kdc_master_key = "MySecretMasterKey123";

int main() {
    // 1. Initialize database connection
    Database db("127.0.0.1", "root", "captyuddy1405", "kerberos_db");
    if (!db.connect()) {
        cerr << "[ERROR - MAIN] Failed to connect to database" << endl;
        return 1;
    }
    cout << "[INFO - MAIN] Successfully connected to database" << endl;

    // 2. Initialize servers
    AuthenticationServer AS(db);
    TicketGrantingServer TGS(db);
    ServiceServer SS(db);

    // 3. Set up the Kerberos protocol
    KerberosProtocol kerberos(AS, TGS, SS, db);

    // 5. Demonstrate user management
    cout << "\n========== User Management Demonstration ==========\n";

    // Add a new user
    string newUsername = "bob";
    string newPassword = "securepass123";

    if (AS.AddUser(newUsername, newPassword)) {
        cout << "[INFO - MAIN] User " << newUsername << " added successfully" << endl;
    }

    // Test authentication with the new user
    if (AS.AuthenticateUser(newUsername, newPassword)) {
        cout << "[INFO - MAIN] Authentication successful for " << newUsername << endl;
    }
    else {
        cout << "[ERROR - MAIN] Authentication failed for " << newUsername << endl;
    }

    // 6. Create a client for the new user
    Client client(newUsername, newPassword);

    // 7. Full Kerberos authentication flow
    cout << "\n========== Full Kerberos Authentication Flow ==========\n";

    // Step 1: Authenticate with AS and get TGT
    cout << "---- Step 1: Authenticating with Authentication Server ----\n";

    string encryptedTGT = kerberos.authenticateClient(client);

    if (encryptedTGT.empty()) {
        cout << "[ERROR - MAIN] Authentication failed" << endl;
        return 0;
    }

    cout << "[INFO - MAIN] Authentication successful, received TGT" << endl;
    cout << "Encrypted TGT: " << encryptedTGT << endl;

    // Step 2: Request service ticket from TGS
    cout << "\n---- Step 2: Requesting Service Ticket from TGS ----\n";

    string serviceName = "FileService";
    string encryptedServiceTicket = kerberos.requestServiceTicket(client, encryptedTGT, serviceName);

    if (encryptedServiceTicket.empty()) {
        cout << "[ERROR - MAIN] Failed to obtain service ticket" << endl;
        return 0;
    }

    cout << "[INFO - MAIN] Successfully obtained service ticket for " << serviceName << endl;
    cout << "Encrypted ST: " << encryptedServiceTicket << endl;

    // Step 3: Access the service
    cout << "\n---- Step 3: Accessing Service with Service Ticket ----\n";

    if (kerberos.accessService(client, encryptedServiceTicket, serviceName)) {
        cout << "[INFO - MAIN] Successfully accessed " << serviceName << endl;
    }
    else {
        cout << "[ERROR - MAIN] Failed to access " << serviceName << endl;
        return 1;
    }
 
    // 8. Optional: Clean up (remove test user)
    cout << "\n========== Cleanup ==========\n";
    if (AS.RemoveUser(newUsername)) {
        cout << "[INFO - MAIN] User " << newUsername << " removed successfully" << endl;
    }

    cout << "\n[INFO - MAIN] Kerberos demonstration completed successfully" << endl;
    return 0;
}