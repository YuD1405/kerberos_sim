#include "client.h"
#include "global.h"
#include <windows.h>

bool Client::Request_TGT(AuthenticationServer& AS) {
    cout << "[REQUEST - CLIENT] Sending authentication request for user " << username << "...\n";
    if (!AS.AuthenticateUser(username, password)) {
        //cerr << "[ERROR - CLIENT] User does not exist or Wrong Password.\n";
        return 0;
    }

    Sleep(3000);

    // Generate TGT for the authenticated user
    encrypted_return = AS.Generate_sk_ticket(username, password);

    // Store ticket 
    encrypted_tgt = encrypted_return.second;
    
    // Store session key 1
    encrypted_session_key_1 = encrypted_return.first;  // SSK1 được mã hóa bằng password

    if (!encrypted_session_key_1.empty() && !encrypted_tgt.empty()) {
        cout << "[INFO - CLIENT] Client \"" << username << "\" : Received TGT.Authentication successful!\n";
        return 1;
    }
    else {
        cerr << "[ERROR - CLIENT] Received ticket failed.\n";
        return 0;
    }
}

bool Client::Request_ServiceTicket(TicketGrantingServer& TGS, const string& service_name) {
    // Decr sk1 by pw 
    string pass = password;
    vector<unsigned char> password = vector<unsigned char>(pass.begin(), pass.end());
    string decrypted_session_key_1 = Encryption::Decrypt(encrypted_session_key_1, password);
    session_key_1 = decrypted_session_key_1;

    // Check if there are available ST for that user and service
    if (TGS.CheckExistST(username, service_name)) {
        existST = true;
        cout << "\n--------------- Get exists ticket ---------------" << endl;
        auto serverReturn = TGS.getServiceTicket(username, service_name);
        encrypted_service_ticket = serverReturn.first;
        encrypted_session_key_2 = serverReturn.second;

        if (!encrypted_service_ticket.empty() || !encrypted_session_key_2.empty()) {
            cout << "[INFO - CLIENT] Client \"" << username << "\" : Received Service Ticket !\n";
            cout << "-------------------------------------------------" << endl;

            return 1;
        }
        else {
            cerr << "[ERROR - CLIENT] Client \"" << username << "\" : Received ST / session key failed.\n";
            cout << "-------------------------------------------------" << endl;

            return 0;
        }
    }
    existST = false;
    // Create authenticator
    time_t timestamp = time(nullptr);
    string authenticator = username + "|" + to_string(timestamp);

    // Encr by sk1
    vector<unsigned char> sk1_vec(decrypted_session_key_1.begin(), decrypted_session_key_1.end());
    string encrypted_authenticator = Encryption::Encrypt(authenticator, sk1_vec);

    // Request
    cout << "[REQUEST - CLIENT] Sending service request by user " << username << " for service: " << service_name << "...\n";
    if (!TGS.Validate_TGT(encrypted_tgt, encrypted_authenticator)) {
        cerr << "[ERROR - CLIENT] Validate ticket failed.\n";
        return 0;
    }
    Sleep(3000);
    // Server return 
    auto gen_return = TGS.Generate_sk_Ticket(username, service_name, encrypted_tgt);

    // Store ST
    encrypted_service_ticket = gen_return.second;

    // Store ssk2
    encrypted_session_key_2 = gen_return.first;

    if (!encrypted_service_ticket.empty() || !encrypted_session_key_2.empty()) {
        cout << "[INFO - CLIENT] Client \"" << username << "\" : Received Service Ticket !\n";
        return 1;
    }
    else {
        cerr << "[ERROR - CLIENT] Client \"" << username << "\" : Received ST / session key failed.\n";
        return 0;
    }
}

bool Client::Access_Service(ServiceServer& SS, const string& service_name) {
    if (existST) {
        bool res = SS.Grant_Access(username, service_name);
        if (!res) {
            //cout << "[ERROR - CLIENT] Client \"" << username << "\" : Access failed " << endl;
            return 0;
        }
        //cout << "[INFO - CLIENT] Client \"" << username << "\" : Accessible for " + service_name << endl;
        return 1;
    }

    // Decr sk2 by sk1
    vector<unsigned char> sk1_vec = vector<unsigned char>(session_key_1.begin(), session_key_1.end());
    string decrypted_session_key_2 = Encryption::Decrypt(encrypted_session_key_2, sk1_vec);

    // Create authenticator
    time_t timestamp = time(nullptr);
    string authenticator = username + "|" + to_string(timestamp);

    // Encr authenticator by sk2
    vector<unsigned char> sk2_vec(decrypted_session_key_2.begin(), decrypted_session_key_2.end());
    string encrypted_authenticator = Encryption::Encrypt(authenticator, sk2_vec);

    cout << "[INFO - CLIENT] Accessing to service: " << service_name << "...\n";

    if (!SS.Validate_Service_Ticket(encrypted_service_ticket, encrypted_authenticator, service_name)) {
        cerr << "[ERROR - CLIENT] Validate service ticket failed.\n";
        return 0;
    }
    Sleep(3000);
    bool res = SS.Grant_Access(username ,service_name);
    if (!res) {
        //cout << "[ERROR - CLIENT] Client \"" << username << "\" : Access failed "<< endl;
        return 0;
    }
    //cout << "[INFO - CLIENT] Client \"" << username << "\" : Accessible for " + service_name << endl;
    return 1;
}