#include <iostream>
#include <string>
#include "email.hpp"
#define ASIO_STANDALONE
#include <asio.hpp>

using namespace std;

int main()
{
    asio::ssl::context sslContext(asio::ssl::context::tlsv12_client);
    sslContext.add_verify_path("/etc/ssl/certs");
    asio::io_context ioc;
    EPostMan postMan(sslContext, ioc, "smtp.gmail.com", 465, "USER@gmail.com", "PASSWORD");
    postMan.send(EMail{"DEST@outlook.com", "SUBJECT", "BODY"},
        [](EPostMan::ErrorCode ec) {
            if(ec) {
                cout << "error sending email" << endl;
            }
            else {
                cout << "email sent!" << endl;
            }
        });
    ioc.run();
}
