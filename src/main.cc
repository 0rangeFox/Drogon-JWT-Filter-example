#include <drogon/drogon.h>

using namespace drogon;

int main() {
    // Load config file
    app().loadConfigFile("./config.json");

    // CORS Policy - Allow connections from anywhere
    app().registerPostHandlingAdvice([](const HttpRequestPtr &req, const HttpResponsePtr &resp) {
        resp->addHeader("Access-Control-Allow-Origin", "*");
    });

    // Run HTTP framework,the method will block in the internal event loop
    app().run();

    return 0;
}
