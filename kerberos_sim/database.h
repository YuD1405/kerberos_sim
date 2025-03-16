#ifndef DATABASE_H
#define DATABASE_H

#include <iostream>
#include <string>
#include <memory>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>

using namespace std;

class Database {
public:
    Database(const string& host, const string& user, const string& password, const string& dbname);
    ~Database();

    bool connect();
    void disconnect();
    bool executeNonQuery(const string& query); // INSERT, UPDATE, DELETE
    vector<map<string, string>> executeSelectQuery(const string& query);

private:
    string host;
    string user;
    string password;
    string dbname;

    sql::mysql::MySQL_Driver* driver;
    unique_ptr<sql::Connection> conn;
};

#endif // DATABASE_H
