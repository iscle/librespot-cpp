#include <iostream>
#include "data/base62.h"
#include "session.h"
#include "diffie_hellman.h"

int main() {
    //GOOGLE_PROTOBUF_VERIFY_VERSION;

    Session session = Session::create();
    session.connect();

    //google::protobuf::ShutdownProtobufLibrary();
    return 0;
}
