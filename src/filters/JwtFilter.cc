#include "JwtFilter.h"

using namespace api::v1::filters;

void JwtFilter::doFilter(const HttpRequestPtr &request, FilterCallback &&fcb, FilterChainCallback &&fccb) {
    // Skip the verification on method Options
    if (request->getMethod() == HttpMethod::Options) return fccb();

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

    std::map<std::string, any> jwtAttributes = JWT::decodeToken(token);
    if (jwtAttributes.empty()) {
        Json::Value resultJson;
        resultJson["error"] = "Token is invalid!";
        resultJson["status"] = 0;

        auto res = HttpResponse::newHttpJsonResponse(resultJson);
        res->setStatusCode(k401Unauthorized);

        return fcb(res);
    }

    // Save the claims on attributes, for on next endpoint to be accessible
    for (auto& attribute : jwtAttributes)
        request->getAttributes()->insert("jwt_" + attribute.first, attribute.second);

    // If everything is right, just move to other endpoint
    return fccb();
}
