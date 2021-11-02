#pragma once

#include <drogon/drogon.h>
#include <drogon/HttpController.h>
#include <src/utils/jwt/JWT.h>

using namespace drogon;
using namespace api::utils::jwt;
namespace api::v1 {
    class Auth : public HttpController<Auth> {
    public:
        METHOD_LIST_BEGIN
            METHOD_ADD(Auth::getToken, "/login", Post, Options);
			METHOD_ADD(Auth::verifyToken, "/verify", Get, Options, "api::v1::filters::JwtFilter");
        METHOD_LIST_END

        void getToken(const HttpRequestPtr &request, std::function<void(const HttpResponsePtr &)> &&callback);
		void verifyToken(const HttpRequestPtr &request, std::function<void(const HttpResponsePtr &)> &&callback);
    };
}
