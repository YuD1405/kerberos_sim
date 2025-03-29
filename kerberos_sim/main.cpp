#include <iostream>
#include "kerberos_protocol.h"
#include "authentication_server.h"
#include "ticket_granting_server.h"
#include "service_server.h"
#include "database.h"
#include "client.h"
#include "global.h"

void clearScreen() {
    cout << "\033[2J\033[H";
}

string kdc_master_key = "MySecretMasterKeyABCDEF123456789";

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

    system("pause");
    clearScreen();

    // 6. Create a client for the new user
    string newUsername = "alice", newPassword = "alicePassword";
    Client client(newUsername, newPassword);

    // 7. Full Kerberos authentication flow
    //cout << "========== Full Kerberos Authentication Flow ==========\n";

    // Step 1: Authenticate with AS and get TGT
    cout << "---- Step 1: Authenticating with Authentication Server ----\n";

    if (!kerberos.phase_1(client)) {
        return 0;
    }

    system("pause");
    clearScreen();

    // Step 2: Request service ticket from TGS
    cout << "---- Step 2: Requesting Service Ticket from TGS ----\n";

    string serviceName = "Image";
    if (!kerberos.phase_2(client, serviceName)) {
        return 0;
    }

    system("pause");
    clearScreen();

    // Step 3: Access the service
    cout << "---- Step 3: Accessing Service with Service Ticket ----\n";

    if (!kerberos.phase_3(client, serviceName)) {
        return 0;
    }

    cout << "\n[INFO - MAIN] Kerberos demonstration completed successfully" << endl;
    return 0;
}