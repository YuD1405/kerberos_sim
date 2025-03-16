#include "database.h"

Database::Database(const string& host, const string& user, const string& password, const string& dbname)
    : host(host), user(user), password(password), dbname(dbname), driver(nullptr) {}

Database::~Database() {
    disconnect();
}

bool Database::connect() {
    try {
        driver = sql::mysql::get_mysql_driver_instance();
        conn.reset(driver->connect("tcp://" + host + ":3306", user, password));
        conn->setSchema(dbname);
        cout << "[INFO - DB] Connected to DB!\n";
        return true;
    }
    catch (sql::SQLException& e) {
        cerr << "[Error - DB] Can not connect with database: " << e.what() << endl;
        return false;
    }
}

void Database::disconnect() {
    if (conn && conn->isValid()) {  // Kiểm tra kết nối có hợp lệ không
        try {
            conn->close();
            std::cout << "[INFO] DB Disconnected.\n";
        }
        catch (const sql::SQLException& e) {
            std::cerr << "[ERROR] Error while disconnecting: " << e.what() << std::endl;
        }
    }
    conn.reset();  // Giải phóng con trỏ an toàn
}


bool Database::executeNonQuery(const string& query) {
    try {
        unique_ptr<sql::Statement> stmt(conn->createStatement());
        stmt->execute(query);
        return true;
    }
    catch (sql::SQLException& e) {
        cerr << "[ERROR - DB] Error executing query: " << e.what() << endl;
        return false;
    }
}

vector<map<string, string>> Database::executeSelectQuery(const string& query) {
    vector<map<string, string>> results;
    try {
        unique_ptr<sql::Statement> stmt(conn->createStatement());
        unique_ptr<sql::ResultSet> res(stmt->executeQuery(query));

        while (res->next()) {
            map<string, string> row;
            sql::ResultSetMetaData* meta = res->getMetaData();
            int columnCount = meta->getColumnCount();
            for (int i = 1; i <= columnCount; ++i) {
                row[meta->getColumnLabel(i)] = res->getString(i);
            }
            results.push_back(row);
        }
    }
    catch (sql::SQLException& e) {
        cerr << "[ERROR - DB] Error fetching data: " << e.what() << endl;
    }
    return results;
}
