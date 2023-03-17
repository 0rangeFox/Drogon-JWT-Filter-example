#include "JWT.h"

using namespace api::utils::jwt;

JWT JWT::generateToken(const std::map<std::string, ::jwt::traits::kazuho_picojson::value_type>& claims, const bool& extension) {
    const auto time = std::chrono::system_clock::now();

    // If remember is true, just add more 30 days, otherwise, just put valid only for 1 day.
    const int64_t expiresAt = std::chrono::duration_cast<std::chrono::seconds>((time + std::chrono::hours{(extension ? 30 : 1) * 24}).time_since_epoch()).count();

    auto jwtToken = ::jwt::create()
        .set_type("JWT")
        .set_issuer(app().getCustomConfig()["jwt"]["issuer"].asString())
        .set_audience(app().getCustomConfig()["jwt"]["audience"].asString())
        .set_issued_at(time)
        .set_not_before(time)
        .set_expires_at(std::chrono::system_clock::from_time_t(expiresAt));

    for (auto& claim : claims)
        jwtToken.set_payload_claim(claim.first, claim.second);

    return {
        jwtToken.sign(::jwt::algorithm::hs256{app().getCustomConfig()["jwt"]["private_key"].asString()}),
        expiresAt
    };
}

std::map<std::string, any> JWT::decodeToken(const std::string& encodedToken) {
    // Let's decode it, if isn't a valid token of JWT, catch will be called
    try {
        auto decodedToken = ::jwt::decode<::jwt::traits::kazuho_picojson>(encodedToken);

        if (verifyToken(decodedToken)) {
            std::map<std::string, any> attributes = {};

            // Save the claims on attributes
            for (auto& claim : decodedToken.get_payload_json())
                addClaimToAttributes(attributes, { claim.first, decodedToken.get_payload_claim(claim.first) });

            return attributes;
        }

        throw;
    } catch (const std::exception& e) {
        return {};
    }
}

bool JWT::verifyToken(const ::jwt::decoded_jwt<::jwt::traits::kazuho_picojson>& jwt) {
    // Let's create a verifier
    auto jwtVerifier = ::jwt::verify()
        .with_issuer(app().getCustomConfig()["jwt"]["issuer"].asString())
        .with_audience(app().getCustomConfig()["jwt"]["audience"].asString())
        .allow_algorithm(::jwt::algorithm::hs256{app().getCustomConfig()["jwt"]["private_key"].asString()});

    // If some properties of token doesn't correspond same as like, issued, audience, etc..., catch will be called
    try {
        jwtVerifier.verify(jwt);
        return true;
    } catch(const ::jwt::error::token_verification_exception& e) {
        return false;
    }
}

void JWT::addClaimToAttributes(std::map<std::string, any>& attributes, const std::pair<std::string, ::jwt::basic_claim<::jwt::traits::kazuho_picojson>>& claim) {
    switch (claim.second.get_type()) {
        case ::jwt::json::type::boolean:
            attributes.insert(std::pair<std::string, bool>(claim.first, claim.second.as_boolean()));
            break;
        case ::jwt::json::type::integer:
            attributes.insert(std::pair<std::string, std::int64_t>(claim.first, claim.second.as_integer()));
            break;
        case ::jwt::json::type::number:
            attributes.insert(std::pair<std::string, double>(claim.first, claim.second.as_number()));
            break;
        case ::jwt::json::type::string:
            attributes.insert(std::pair<std::string, std::string>(claim.first, claim.second.as_string()));
            break;
        case ::jwt::json::type::array:
            attributes.insert(std::pair<std::string, any>(claim.first, claim.second.as_array()));
            break;
        case ::jwt::json::type::object:
            attributes.insert(std::pair<std::string, any>(claim.first, claim.second));
            break;
        default: throw std::bad_cast();
    }
}
