﻿#include "database.h"

Database::Database(const std::string& host, const std::string& user, const std::string& password, const std::string& dbname)
    : host(host), user(user), password(password), dbname(dbname), driver(nullptr) {}

Database::~Database() {
    disconnect();
}

bool Database::connect() {
    try {
        driver = sql::mysql::get_mysql_driver_instance();
        conn.reset(driver->connect("tcp://" + host + ":3306", user, password));
        conn->setSchema(dbname);
        //std::cout << "[INFO - DB] Connected to DB!\n";
        return true;
    }
    catch (sql::SQLException& e) {
        std::cerr << "[Error - DB] Can not connect with database: " << e.what() << std::endl;
        return false;
    }
}

void Database::disconnect() {
    if (conn) {
        conn->close();
        std::cout << "[INFO] Disconnected.\n";
    }
}

bool Database::executeQuery(const std::string& query) {
    try {
        std::unique_ptr<sql::Statement> stmt(conn->createStatement());
        stmt->execute(query);
        std::cout << "[INFO - DB] Query executed!\n";
        return true;
    }
    catch (sql::SQLException& e) {
        std::cerr << "[ERROR - DB] Bug executing query: " << e.what() << std::endl;
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
