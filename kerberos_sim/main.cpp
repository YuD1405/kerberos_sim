#include <iostream>
#include "kerberos_protocol.h"
#include "authentication_server.h"
#include "ticket_granting_server.h"
#include "service_server.h"
#include "database.h"
#include "client.h"
#include "global.h"
#include <windows.h>

void clearScreen() {
    cout << "\033[2J\033[H";
}

string kdc_master_key = "MySecretMasterKeyABCDEF123456789";

// "Alice123" - "SecurePassAlice1";
// "Bob456" - "StrongPassBob2";
// "Charlie789" - "CharlieSafeKey3";
// "David321" - "DavidProtected4";
// "Eve654" - "EveSuperSecure5"
// "yuddy1405" - "captyuddy1405"

int main() {
   
    cout << "Initiating system..." << endl;
    //Sleep(3000);

    // 1. Initialize database connection
    Database db("127.0.0.1", "root", "captyuddy1405", "kerberos_db");
    if (!db.connect()) {
        cerr << "[ERROR] Failed to connect to database" << endl;
        return 1;
    }
    cout << "[INFO] Successfully connected to database" << endl;

    // 2. Initialize servers
    AuthenticationServer AS(db);
    TicketGrantingServer TGS(db);
    ServiceServer SS(db);
    //Sleep(1000);
    cout << "[INFO] Authentication Server initiated" << endl;
    //Sleep(1000);
    cout << "[INFO] Ticket Granting Server initiated" << endl;
    //Sleep(1000);
    cout << "[INFO] Service Server initiated" << endl;

    // 3. Set up the Kerberos protocol
    KerberosProtocol kerberos(AS, TGS, SS, db);

    system("pause");
    clearScreen();

    // 4. Create a client for the new user
    string newUsername = "Alice123", newPassword = "SecurePassAlice1";
    //cout << "Username: "; cin >> newUsername;
    //cout << "Password: "; cin >> newPassword;
    Client client(newUsername, newPassword);
    cout << "Press Any button to Login..." << endl;
    system("pause");
    clearScreen();

    // 6. Full Kerberos authentication flow
    //Step 1: Authenticate with AS and get TGT
    cout << "---- Step 1: Authenticating with Authentication Server ----\n";

    if (!kerberos.phase_1(client)) {
        return 0;
    }

    system("pause");
    clearScreen();

    // Step 2: Request service ticket from TGS
    cout << "---- Step 2: Requesting Service Ticket from TGS ----\n";
    string serviceName;

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

    system("pause");
    clearScreen();

    cout << "\n[INFO - MAIN] Kerberos demonstration completed successfully" << endl;
    return 0;
}

//Init Data
//int main() {
//    // 1. Initialize database connection
//    Database db("127.0.0.1", "root", "captyuddy1405", "kerberos_db");
//    if (!db.connect()) {
//        cerr << "[ERROR] Failed to connect to database" << endl;
//        return 1;
//    }
//    cout << "[INFO] Successfully connected to database" << endl;
//
//    // 2. Initialize servers
//    AuthenticationServer AS(db);
//    TicketGrantingServer TGS(db);
//    ServiceServer SS(db);
//    
//    // 3. Create Data
//    // Thêm 5 người dùng với mật khẩu dưới 32 ký tự
//    AS.AddUser("Alice123", "SecurePassAlice1");
//    AS.AddUser("Bob456", "StrongPassBob2");
//    AS.AddUser("Charlie789", "CharlieSafeKey3");
//    AS.AddUser("David321", "DavidProtected4");
//    AS.AddUser("Eve654", "EveSuperSecure5");
//
//    // Thêm 5 dịch vụ với service key đúng 32 ký tự số
//    SS.Add_Service("FileService", "12345678901234567890123456789012");
//    SS.Add_Service("EmailService", "23456789012345678901234567890123");
//    SS.Add_Service("DatabaseService", "34567890123456789012345678901234");
//    SS.Add_Service("CloudStorage", "45678901234567890123456789012345");
//    SS.Add_Service("PaymentGateway", "56789012345678901234567890123456");
//
//    return 0;
//}