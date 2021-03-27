#pragma once

#include <drogon/drogon.h>
#include <drogon/HttpController.h>
#include <jwt-cpp/jwt.h>

using namespace drogon;
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
