//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_CONTEXT_HPP
#define HEAAN_TEST_CONTEXT_HPP
#include <HEAAN.h>
#include <memory>

namespace EasyHEAAN {
    struct Context {
        std::shared_ptr<Scheme> scheme;
        long logp;

        Context(std::shared_ptr<Scheme> scheme, long logp): scheme(scheme), logp(logp) {}
        Context() = delete;
        Context(const Context&) = default;
        Context(Context&&) = default;
        Context& operator =(const Context&) = default;
        Context& operator =(Context&&) = default;
    };
}

#endif //HEAAN_TEST_CONTEXT_HPP
