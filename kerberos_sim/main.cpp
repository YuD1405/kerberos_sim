#include <iostream>
#include "kerberos_protocol.h"

int main() {
    // khởi tạo db
    Database db("127.0.0.1", "root", "DangDuy06072004!", "kerberos_db");
    if (db.connect()) {
        cout << "Connected with DB" << endl;
    }
    else {
        cout << "Fail to connect with DB" << endl;
        return 0;
    }

    // Khởi tạo user
    string username = "alice";
    string password = "password123";
    Client user_1(username, password);

    // Khởi tạo các server
    AuthenticationServer AS;
    TicketGrantingServer TGS(db);
    ServiceServer SS;

    // Khởi tạo protocol
    KerberosProtocol kerberos(AS, TGS, SS, db);

    // KDC master key 
    string kdc_master_key = "master_key_of_quang_duy";
	vector<unsigned char> kdc_master_key_vector(kdc_master_key.begin(), kdc_master_key.end());

    // Bước 1: Xác thực với Authentication Server
    cout << "---------------Xac thuc voi Authen Server---------------" << endl;
    string encryptedTGT = kerberos.authenticateClient(user_1);
    if (encryptedTGT.find("[ERROR - KERBEROS]") != string::npos) {
        cout << "[ERROR - MAIN] Login Failed!" << endl;
        return 0;
    }
    else {
        cout << "[INFO - MAIN] Login Successfully!" << endl;
    }
    cout << endl;

    // Bước 2: Yêu cầu vé dịch vụ từ TGS
    cout << "---------------Yeu cau ve dich vu tu TGS---------------" << endl;
    string serviceName = "FileServer";
    string encryptedServiceTicket = kerberos.requestServiceTicket(user_1, encryptedTGT, serviceName);

    if (encryptedServiceTicket.find("[ERROR - KERBEROS]") != string::npos) {
        cout << "[ERROR - MAIN] Receive ST Failed!" << endl;
        return 0;
    }
    else {
        cout << "[INFO - MAIN] Receive ST Successfully!" << endl;
    }
    cout << endl;

    // Bước 3: Truy cập dịch vụ
    cout << "---------------Truy cap dich vu---------------" << endl;
    if (kerberos.accessService(user_1, encryptedServiceTicket, serviceName)) {
        cout << "[INFO - MAIN] Access Service Successfully!" << endl;
    }
    else {
        cout << "[ERROR - MAIN] Access to Service Failed!" << endl;
        return 0;
    }

    return 0;
}
