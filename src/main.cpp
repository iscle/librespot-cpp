#include "data/base62.h"
#include "session.h"

int main() {
    //GOOGLE_PROTOBUF_VERIFY_VERSION;

    Session *session = Session::create();
    session->connect();

    spotify::LoginCredentials login_credentials;
    login_credentials.set_typ(spotify::AUTHENTICATION_USER_PASS);
    login_credentials.set_username("albertiscle9@gmail.com");
    login_credentials.set_auth_data("");
    session->authenticate(login_credentials);

    delete session;
    //google::protobuf::ShutdownProtobufLibrary();
    return 0;
}
