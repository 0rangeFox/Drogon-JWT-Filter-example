#include "Auth.h"

using namespace api::v1;

void Auth::getToken(const HttpRequestPtr &request, std::function<void(const HttpResponsePtr &)> &&callback) {
    Json::Value responseJson = *request->getJsonObject();
    Json::Value resultJson;

    // Verify if there's a missing values on body of request
    if (!responseJson.isMember("email") || !responseJson.isMember("password")) {
        resultJson["error"] = "Missing email or password.";
		resultJson["status"] = 0;

        return callback(HttpResponse::newHttpJsonResponse(resultJson));
    }

    const bool responseRemember = responseJson.isMember("remember") && responseJson["remember"].asBool();

    const auto time = std::chrono::system_clock::now();
    // If remember is true, just add more 30 days, otherwise, just put valid only for 1 day.
    const long long expireAt = std::chrono::duration_cast<std::chrono::seconds>((time + std::chrono::hours{(responseRemember ? 30 : 1) * 24}).time_since_epoch()).count();

    auto jwtToken = jwt::create()
            .set_type("JWT")
            .set_issuer(app().getCustomConfig()["jwt"]["issuer"].asString())
            .set_audience(app().getCustomConfig()["jwt"]["audience"].asString())
            .set_issued_at(time)
            .set_not_before(time)
            .set_expires_at(std::chrono::system_clock::from_time_t(expireAt))
            .set_payload_claim("email", jwt::claim(responseJson["email"].asString()))
            .sign(jwt::algorithm::hs256{app().getCustomConfig()["jwt"]["private_key"].asString()});

    resultJson["token"] = jwtToken;
    resultJson["expiresIn"] = (int) (expireAt - std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count());
    resultJson["expiresAt"] = (int) expireAt;
    resultJson["status"] = 1;

    return callback(HttpResponse::newHttpJsonResponse(resultJson));
}

void Auth::verifyToken(const HttpRequestPtr &request, std::function<void(const HttpResponsePtr &)> &&callback) {
    Json::Value resultJson;

    int timeToken = request->getAttributes()->get<int>("jwt_expiresAt");
    int timeNow = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    resultJson["expiresIn"] = timeToken - timeNow;
    resultJson["expiresAt"] = timeToken;
    resultJson["status"] = 1;

    return callback(HttpResponse::newHttpJsonResponse(resultJson));
}
