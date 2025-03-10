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

class Database {
public:
    Database(const std::string& host, const std::string& user, const std::string& password, const std::string& dbname);
    ~Database();

    bool connect();
    void disconnect();
    bool executeQuery(const std::string& query);
    void fetchData(const std::string& query);

private:
    std::string host;
    std::string user;
    std::string password;
    std::string dbname;

    sql::mysql::MySQL_Driver* driver;
    std::unique_ptr<sql::Connection> conn;
};

#endif // DATABASE_H
