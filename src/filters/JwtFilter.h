#pragma once

#include <drogon/drogon.h>
#include <src/utils/jwt/JWT.h>

using namespace drogon;
using namespace api::utils::jwt;
namespace api::v1::filters {
    class JwtFilter : public HttpFilter<JwtFilter> {
    public:
        JwtFilter() = default;

        virtual void doFilter(const HttpRequestPtr &request, FilterCallback &&fcb, FilterChainCallback &&fccb) override;
    };
}
