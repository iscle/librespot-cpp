//
// Created by Iscle on 26/01/2021.
//

#ifndef LIBRESPOT_C_SESSION_H
#define LIBRESPOT_C_SESSION_H

#include <string>

class Session {
private:

    Session(const std::string& addr);

    class Configuration {

    };

    class ConnectionHolder {
    public:
        static ConnectionHolder create(const std::string &addr);

        void write_int(int data) const;

        void write(const uint8_t *data, size_t size) const;

        void write(const std::string &data) const;

        void write_byte(uint8_t data) const;

        int read_int() const;

        void read_fully(uint8_t *data, size_t len);

    private:
        int sockfd;

        ConnectionHolder(const std::string &addr, const std::string &port);
    };

    ConnectionHolder conn;
public:
    static Session create();
    void connect();
};

#endif //LIBRESPOT_C_SESSION_H
