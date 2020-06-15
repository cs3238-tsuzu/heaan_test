//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_COMPARE_HPP
#define HEAAN_TEST_COMPARE_HPP
#include <HEAAN.h>
#include <cstring>
#include "cipher.hpp"

namespace CKKSCompare {
    std::ostream& operator << (std::ostream& os, EasyHEAAN::Cipher& c) {
        os << "logp: " << c.getCiphertext().logp
           << ", logq: " << c.getCiphertext().logq
            << ", n: " << c.getCiphertext().n;

        return os;
    }

//    using namespace std;
    using namespace NTL;
    using namespace EasyHEAAN;

    Cipher inv(const Cipher& x, std::size_t d) {
        auto mx = -x;

        auto ax = mx + 2;
        ax.modDownInplace();

        auto bx = mx + 1;

        for(std::size_t i = 0; i < d; ++i) {
            bx *= bx;
            bx.rescaleByInplace();

            ax *= bx + 1;
            ax.rescaleByInplace();
        }

        return ax;
    }

    Cipher sqrt(const Cipher& x, std::size_t d) {
        auto ax = x;
        auto bx = x - 1;

        for(std::size_t i = 0; i < d; ++i) {
            auto x = -bx / 2 + 1;
            x.rescaleByInplace();

            ax.modDownInplace();
            ax *= x;
            ax.rescaleByInplace();

            if (i + 1 == d) {
                break;
            }

            auto s = bx * bx;
            s.rescaleByInplace();
            auto t = (bx - 3) / 4;
            t.rescaleByInplace();

            bx = s * t;
            bx.rescaleByInplace();
        }

        return ax;
    }
}

#endif //HEAAN_TEST_COMPARE_HPP
