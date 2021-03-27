#pragma once

#include <drogon/drogon.h>
#include <jwt-cpp/jwt.h>

using namespace drogon;
namespace api::v1::filters {
    class JwtFilter : public HttpFilter<JwtFilter> {
    public:
        JwtFilter() = default;

        virtual void doFilter(const HttpRequestPtr &request, FilterCallback &&fcb, FilterChainCallback &&fccb) override;
    };
}
