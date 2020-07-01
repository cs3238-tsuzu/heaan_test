//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_COMPARE_HPP
#define HEAAN_TEST_COMPARE_HPP
#include <HEAAN.h>
#include <cstring>
#include <iterator>
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

    template<typename Iterator>
    Cipher sum(Iterator begin, Iterator end) {
        if(begin == end) {
            throw std::runtime_error("must contain >0 values");
        }

        auto sum = *begin;
        for(auto it = std::next(begin); it != end; std::advance(it, 1)) {
            sum += *it;
        }

        return sum;
    }

    Cipher sum(const std::vector<Cipher>& a) {
        return sum(a.begin(), a.end());
    }

    std::vector<Cipher> maxIdx(const std::vector<Cipher>& a, int d, int d_, int m, int t) {
        std::cout << "logQ" << a[0].getCiphertext().logq << std::endl;
        auto inv = ::CKKSCompare::inv(
            (sum(a) / a.size()).rescaleByInplace(),
            d_
        );
        // (d_ + 1) + 1

        std::cout << "logQ" << inv.getCiphertext().logq << std::endl;

        std::vector<Cipher> b;
        b.reserve(a.size());
        for(int i = 0; i < a.size() - 1; ++i) {
            auto ai = a[i].modDownTo(inv);
            ai *= inv;
            ai.rescaleByInplace();
            ai /= a.size();
            ai.rescaleByInplace();
            b.emplace_back(std::move(ai));
        }
        b.emplace_back(-sum(b)+1);
        // 2

        std::cout << b[0].getCiphertext().logq << std::endl;

        const int levelDown = static_cast<int>(std::log2(m)) + d + 2;
        for(int i = 0; i < t; ++i) {
            if ((levelDown + 1) * b[0].getCiphertext().logp > b[0].getCiphertext().logq) {
                for(auto& c : b) {
                    c.bootstrapInplace();
                }
            }

            for(auto& c : b) {
                c = c.pow(m);
            }
            // floor(log m)

            auto inv = ::CKKSCompare::inv(sum(b), d);
            // d + 1

            for(int j = 0; j < b.size() - 1; ++j) {
                b[j].modDownToInplace(inv);
                b[j] *= inv;
                b[j].rescaleByInplace();
            }
            // 1

            b[b.size() - 1] = -CKKSCompare::sum(b.begin(), std::prev(b.end())) + 1;

            std::cout << b[0].getCiphertext().logq << std::endl;
        }

        return b;
    }
//    Cipher comp(const Cipher& a, const Cipher& b, std::size_t d, std::size_t d_, std::size_t t, std::size_t m) {
//        auto at = a / 2;
//
//        at *= inv(((a+b) / 2).rescaleByInplace(), d);
//        at.rescaleByInplace();
//
//        auto bt = -at+1;
//
//        for(std::size_t i = 0; i < t; ++i) {
//
//        }
//    }
}

#endif //HEAAN_TEST_COMPARE_HPP
