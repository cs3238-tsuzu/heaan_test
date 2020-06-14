//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_COMPARE_HPP
#define HEAAN_TEST_COMPARE_HPP
#include <HEAAN.h>
#include <cstring>
#include "cipher.hpp"

namespace CKKSCompare {
//    using namespace std;
    using namespace NTL;
    using namespace EasyHEAAN;

    Cipher inv(const Cipher& x, std::size_t d) {
        auto mx = -x;

        auto ax = mx + 2;
        ax.modDownInplace();

        auto bx = mx + 1;

        for(std::size_t i = 0; i < d; ++i) {
            bx.squareInplace().rescaleByInplace();

            ax *= bx + 1;
            ax.rescaleByInplace();
        }

        return ax;
    }

    Cipher sqrt(const Cipher& x, std::size_t d) {
        auto ax = x;
        auto bx = x + 1;

        for(std::size_t i = 0; i < d; ++i) {
            ax = ax * (-bx * 0.5 + 1);
            bx = bx.square() * ((bx+-3) * (.25));
        }

        return ax;
    }
}

#endif //HEAAN_TEST_COMPARE_HPP
