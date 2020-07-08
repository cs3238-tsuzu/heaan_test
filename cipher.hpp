//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_CIPHER_HPP
#define HEAAN_TEST_CIPHER_HPP

#include <HEAAN.h>
#include <memory>
#include <stdexcept>
#include "context.hpp"

constexpr bool useValidation = true;

namespace EasyHEAAN {
    class Cipher : private Context {
        Ciphertext cipher;

    private:
        inline
        void validate(const Cipher& rh_) const {
            if constexpr(useValidation) {
                const auto lh = this->getCiphertext();
                const auto rh = rh_.getCiphertext();

                if (lh.logq != rh.logq) {
                    throw std::runtime_error("logq mismatch");
                }
                if (lh.logp != rh.logp) {
                    throw std::runtime_error("logp mismatch");
                }
            }
        }

        inline
        Cipher autoAdjustment(Cipher rh) {
            if constexpr (!useValidation) {
                return rh;
            }

            if (this->getCiphertext().logq < this->logp * 2) {
                this->bootstrapInplace();
            }

            auto diffLogp = this->getCiphertext().logp - rh.getCiphertext().logp;

            if (diffLogp > 0) {
                auto nextLogq = this->getCiphertext().logq - std::abs(diffLogp);

                if (nextLogq < this->logp * 2) {
                    this->bootstrapInplace();
                }

                this->rescaleToInplace(rh);
            }else if (diffLogp < 0) {
                auto nextLogq = rh.getCiphertext().logq - std::abs(diffLogp);

                if (nextLogq < this->logp * 2) {
                    rh.bootstrapInplace();
                }

                rh.rescaleToInplace(*this);
            }

            if (this->getCiphertext().logq > rh.getCiphertext().logq) {
                this->modDownToInplace(rh);
            } else if (this->getCiphertext().logq < rh.getCiphertext().logq) {
                rh.modDownToInplace(*this);
            }

            return std::move(rh);
        }

    public:
        Cipher(const Context &ctx) : Context(ctx) {}

        Cipher(const Context &ctx, const Ciphertext &c) : Context(ctx), cipher(c) {}

        Cipher(const Context &ctx, Ciphertext &&c) : Context(ctx), cipher(c) {}

        Cipher(const Cipher &) = default;

        Cipher(Cipher &&) = default;

        Cipher &operator=(const Cipher &) = default;

        Cipher &operator=(Cipher &&) = default;

        Cipher operator()(long dlogpUnit = 1) const {
            return this->rescaleBy(dlogpUnit);
        }

        Cipher rescaleBy(long dlogpUnit = 1) const {
            dlogpUnit *= this->logp;

            Ciphertext res;
            this->scheme->reScaleBy(res, const_cast<Ciphertext &>(this->cipher), dlogpUnit);

            return Cipher(*this, std::move(res));
        }

        Cipher &rescaleByInplace(long dlogpUnit = 1) {
            dlogpUnit *= this->logp;

            this->scheme->reScaleByAndEqual(this->cipher, dlogpUnit);

            return *this;
        }

        Cipher rescaleTo(const Cipher &c) const {
            Ciphertext res;
            this->scheme->reScaleTo(res, const_cast<Ciphertext &>(this->cipher), c.getCiphertext().logp);

            return Cipher(*this, std::move(res));
        }

        Cipher &rescaleToInplace(const Cipher &c) {
            this->scheme->reScaleToAndEqual(this->cipher, c.getCiphertext().logp);

            return *this;
        }

        Cipher modDown(long dlogpUnit = 1) const {
            dlogpUnit *= this->logp;

            Ciphertext res;
            this->scheme->modDownBy(res, const_cast<Ciphertext &>(this->cipher), dlogpUnit);

            return Cipher(*this, std::move(res));
        }

        Cipher &modDownInplace(long dlogpUnit = 1) {
            dlogpUnit *= this->logp;

            this->scheme->modDownByAndEqual(this->cipher, dlogpUnit);

            return *this;
        }

        Cipher modDownTo(const Cipher& c) const {
            Ciphertext res;
            this->scheme->modDownTo(res, const_cast<Ciphertext&>(this->getCiphertext()), c.getCiphertext().logq);

            return Cipher(*this, std::move(res));
        }

        Cipher &modDownToInplace(const Cipher& c) {
            this->scheme->modDownToAndEqual(this->cipher, c.getCiphertext().logq);

            return *this;
        }


        Cipher operator+(const Cipher &rh) const {
            if (this->scheme != rh.scheme) {
                throw std::runtime_error("scheme mismatch");
            }
            this->validate(rh);

            Ciphertext res;
            this->scheme->add(res, const_cast<Ciphertext &>(this->cipher), const_cast<Ciphertext &>(rh.cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher operator+(double d) const {
            Ciphertext res;
            this->scheme->addConst(res, const_cast<Ciphertext &>(this->cipher), d, this->cipher.logp);

            return Cipher(*this, std::move(res));
        }

        Cipher operator*(const Cipher &rh) const {
            if (this == &rh) {
                return this->square();
            }
            this->validate(rh);

            Ciphertext res;
            this->scheme->mult(res, const_cast<Ciphertext &>(this->cipher), const_cast<Ciphertext &>(rh.cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher operator*(double d) const {
            Ciphertext res;
            this->scheme->multByConst(res, const_cast<Ciphertext &>(this->cipher), d, this->cipher.logp);

            return Cipher(*this, std::move(res));
        }

        Cipher &operator+=(const Cipher &rh) {
            if (this->scheme != rh.scheme) {
                throw std::runtime_error("scheme mismatch");
            }
            this->validate(rh);

            this->scheme->addAndEqual(this->cipher, const_cast<Ciphertext &>(rh.cipher));

            return *this;
        }

        Cipher &operator+=(double d) {
            this->scheme->addConstAndEqual(this->cipher, d, this->cipher.logp);

            return *this;
        }

        Cipher &operator*=(const Cipher &rh) {
            if (this == &rh) {
                return this->squareInplace();
            }
            this->validate(rh);

            this->scheme->multAndEqual(this->cipher, const_cast<Ciphertext &>(rh.cipher));

            return *this;
        }

        Cipher &operator*=(double d) {
            this->scheme->multByConstAndEqual(this->cipher, d, this->cipher.logp);

            return *this;
        }

        Cipher operator-() const {
            Ciphertext res;
            this->scheme->negate(res, const_cast<Ciphertext &>(this->cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher &negate() {
            this->scheme->negateAndEqual(this->cipher);

            return *this;
        }

        Cipher operator-(const Cipher &rh) const {
            return *this - Cipher(rh);
        }

        Cipher operator-(Cipher&& rh) const {
            this->validate(rh);

            return *this + rh.negate();
        }

        Cipher operator-(double d) const {
            return *this + (-d);
        }

        Cipher &operator-=(const Cipher &rh) {
            return *this -= Cipher(rh);
        }

        Cipher &operator-=(Cipher &&rh) {
            this->validate(rh);

            rh.negate();
            *this += rh;

            return *this;
        }

        Cipher &operator-=(double d) {
            return (*this) += -d;
        }

        Cipher operator/(double d) const {
            return (*this) * (1. / d);
        }

        Cipher &operator/=(double d) {
            return (*this) *= (1. / d);
        }

        Cipher square() const {
            Ciphertext res;
            this->scheme->square(res, const_cast<Ciphertext &>(this->cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher &squareInplace() {
            this->scheme->squareAndEqual(this->cipher);

            return *this;
        }

        Cipher pow(int m) const {
            if (m == 0) {
                throw std::runtime_error("m must not be zero");
            }

            auto c = *this;
            while ((m & 1) == 0) {
                c.squareInplace();
                c.rescaleByInplace();
                m >>= 1;
            }

            auto res = c;
            c.squareInplace();
            c.rescaleByInplace();
            m >>= 1;

            if (m == 0) {
                return res;
            }

            res.modDownInplace();

            while (m != 0) {
                if (m & 1) {
                    res *= c;
                    res.rescaleByInplace();
                } else {
                    res.modDownInplace();
                }

                c.squareInplace();
                c.rescaleByInplace();
                m >>= 1;
            }

            return res;
        }

        // Bootstrapping

        Cipher& bootstrapInplace() {
            if(!bs) {
                throw std::runtime_error("Bootstrapping options are not set");
            }

            this->scheme->bootstrapAndEqual(this->getCiphertext(), bs->logq, bs->logQ, bs->logT, bs->logI);

            return *this;
        }

        Cipher left(long r) const {
            Ciphertext res;
            scheme->leftRotateFast(res, const_cast<Ciphertext &>(this->cipher), r);

            return Cipher(*this, std::move(res));
        }

        Cipher& leftInPlace(long r) {
            Ciphertext res;
            scheme->leftRotateFastAndEqual(this->cipher, r);

            return *this;
        }

        Cipher right(long r) const {
            Ciphertext res;
            scheme->rightRotateFast(res, const_cast<Ciphertext &>(this->cipher), r);

            return Cipher(*this, std::move(res));
        }

        Cipher& rightInPlace(long r) {
            Ciphertext res;
            scheme->rightRotateFastAndEqual(this->cipher, r);

            return *this;
        }

        // MSBの桁数を返す
        static long numBits(long n) {
            long k = 0;
            while (n > 0){ k++; n /= 2; }
            return k;
        }

        // i-bit目が立っているかどうかを返す
        static inline bool curBit(long n, long i){
            return n&(1 << i);
        }

        Cipher sumAll() {
            Cipher res = *this, orig = *this;

            long n = 1 << logn;
            if(n == 1) {
                return res;
            }

            long k = numBits(n); // logn + 1と一緒な気がする
            long e = 1;

            for(long i = k - 2; i >= 0; --i) {
                auto tmp = res;
                tmp.leftInPlace(e);
                res += tmp;
                e <<= 1;

                if(curBit(n, i)) {
                    auto tmp = orig;

                    tmp.leftInPlace(-e);
                    res += tmp;

                    e += 1;
                }
            }

            return res;
        }

        Ciphertext &getCiphertext() {
            return this->cipher;
        }

        const Ciphertext &getCiphertext() const {
            return this->cipher;
        }

        Ciphertext &operator->() {
            return this->cipher;
        }
    };
}

#endif //HEAAN_TEST_CIPHER_HPP
