//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_CRYPYO_HPP
#define HEAAN_TEST_CRYPYO_HPP

#include "context.hpp"
#include "cipher.hpp"
#include <initializer_list>
#include <optional>
#include <algorithm>

namespace EasyHEAAN {
    class Crypto: public Context {
        std::optional<SecretKey> secretKey;
        long logq;

    public:
        Crypto(std::shared_ptr<Scheme> scheme, long logp, long logq, long logn): Context(scheme, logp, logn), logq(logq) {}
        Crypto(const Context& c, long logq): Context(c), logq(logq) {}

        template<class InputIterator>
        Cipher encrypt(InputIterator begin, InputIterator end, std::size_t n, double def = 0.) const {
            std::vector<double> vec(n, def);
            std::copy(begin, end, vec.begin());

            Ciphertext res;
            scheme->encrypt(res, vec.data(), n, logp, logq);

            return Cipher(*this, std::move(res));
        }

        Cipher encrypt(const std::initializer_list<double>& arr, std::size_t n = -1, double def = 0.) const {
            return this->encrypt(arr.begin(), arr.end(), n, def);
        }

        void useSecretKey(const SecretKey& sk) {
            this->secretKey = sk;
        }

        void setupBootstrapping(const Bootstrapper& bs) {
            this->bs = bs;
        }

        std::vector<double> decrypt(const Cipher& c) {
            if(!this->secretKey) {
                throw std::runtime_error("secret key is not  set");
            }

            Ciphertext& ct = const_cast<Cipher&>(c).getCiphertext();

            auto v = scheme->decrypt(this->secretKey.value(), ct);

            std::vector<double> res;
            res.reserve(ct.n);
            for(int i = 0; i < ct.n; ++i) {
                res.emplace_back(v[i].real());
            }

            delete[] v;

            return res;
        }

        auto decrypt(const std::vector<Cipher>& c) {
            std::vector<std::vector<double>> res;
            res.reserve(c.size());

            for(auto&& v : c) {
                res.emplace_back(decrypt(v));
            }

            return res;
        }
    };
}

#endif //HEAAN_TEST_CRYPYO_HPP
