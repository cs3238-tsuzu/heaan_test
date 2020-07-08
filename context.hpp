//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_CONTEXT_HPP
#define HEAAN_TEST_CONTEXT_HPP
#include <HEAAN.h>
#include <memory>

namespace EasyHEAAN {
    struct Bootstrapper {
        long logq = 50;
        long logQ = 1200;
        long logT = 2;
        long logI = 4;
    };

    struct Context {
        std::shared_ptr<Scheme> scheme;
        long logp;
        long logn;
        std::optional<Bootstrapper> bs;

        Context(std::shared_ptr<Scheme> scheme, long logp, long logn): scheme(scheme), logp(logp), logn(logn) {}
        Context() = delete;
        Context(const Context&) = default;
        Context(Context&&) = default;
        Context& operator =(const Context&) = default;
        Context& operator =(Context&&) = default;
    };
}

#endif //HEAAN_TEST_CONTEXT_HPP
