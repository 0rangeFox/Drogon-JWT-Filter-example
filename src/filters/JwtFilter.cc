#include "JwtFilter.h"

using namespace api::v1::filters;

void JwtFilter::doFilter(const HttpRequestPtr &request, FilterCallback &&fcb, FilterChainCallback &&fccb) {
    // Skip the verification on method Options
    if (request->getMethod() == HttpMethod::Options) fccb();

    std::string token = request->getHeader("Authorization");

    // If authorization header is empty
    if (token.empty()) {
        Json::Value resultJson;
        resultJson["error"] = "No header authentication!";
        resultJson["status"] = 0;

        auto res = HttpResponse::newHttpJsonResponse(resultJson);
        res->setStatusCode(k401Unauthorized);

        // Return the response and let's tell this endpoint request was cancelled
        return fcb(res);
    }

    // Remove the string "Bearer " on token
    token = token.substr(7);

    // Let's create a verifier
    auto jwtVerifier = jwt::verify()
            .with_issuer(app().getCustomConfig()["jwt"]["issuer"].asString())
            .with_audience(app().getCustomConfig()["jwt"]["audience"].asString())
            .allow_algorithm(jwt::algorithm::hs256{app().getCustomConfig()["jwt"]["private_key"].asString()});

    try {
        // Let's decode it, if isn't a valid token of JWT, catch will be called
        auto tokenDecoded = jwt::decode(token);

        // If some properties of token doesn't correspond same as like, issued, audience, etc..., catch will be called
        jwtVerifier.verify(tokenDecoded);

        // Save the expires time of token on attributes
        int expiresAt = std::chrono::duration_cast<std::chrono::seconds>(tokenDecoded.get_expires_at().time_since_epoch()).count();
        request->getAttributes()->insert("jwt_expiresAt", expiresAt);

        // Save the claims on attributes, for on next endpoint to be accessible
        for (auto& claim : tokenDecoded.get_payload_claims())
            // TODO Fix this ugly converter, make a better ones than calling to_json and convert it to string.
            request->getAttributes()->insert("jwt_" + claim.first, claim.second.to_json().to_str());

        // If everything is right, just move to other endpoint
        return fccb();
    } catch(const std::exception& e) {
        Json::Value resultJson;
        resultJson["error"] = "Token is invalid!";
		resultJson["status"] = 0;

        auto res = HttpResponse::newHttpJsonResponse(resultJson);
        res->setStatusCode(k401Unauthorized);

        return fcb(res);
    }
}
