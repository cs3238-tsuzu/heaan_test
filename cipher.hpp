//
// Created by Tsuzu on 2020/06/14.
//

#ifndef HEAAN_TEST_CIPHER_HPP
#define HEAAN_TEST_CIPHER_HPP

#include <HEAAN.h>
#include <memory>
#include <stdexcept>
#include "context.hpp"

namespace EasyHEAAN {

    class Cipher: private Context {
        Ciphertext cipher;

    public:
        Cipher(const Context& ctx) : Context(ctx) {}
        Cipher(const Context& ctx, const Ciphertext &c) : Context(ctx), cipher(c) {}
        Cipher(const Context& ctx, Ciphertext &&c) : Context(ctx), cipher(c) {}

        Cipher(const Cipher &) = default;
        Cipher(Cipher &&) = default;
        Cipher &operator=(const Cipher &) = default;
        Cipher &operator=(Cipher &&) = default;

        Cipher operator -() const {
            Ciphertext res;
            this->scheme->negate(res, const_cast<Ciphertext&>(this->cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher& negate() {
            this->scheme->negateAndEqual(this->cipher);

            return *this;
        }

        Cipher operator()(double dlogp = -1) const {
            if(dlogp < 0) {
                dlogp = this->logp;
            }

            Ciphertext res;
            this->scheme->reScaleBy(res, const_cast<Ciphertext&>(this->cipher), dlogp);

            return Cipher(*this, std::move(res));
        }

        Cipher rescaleBy(double dlogp = -1) const {
            return this->operator()(dlogp);
        }

        Cipher& rescaleByInplace(double dlogp = -1) {
            if(dlogp < 0) {
                dlogp = this->logp;
            }

            this->scheme->reScaleByAndEqual(this->cipher, dlogp);

            return *this;
        }

        Cipher modDown(double dlogp = -1) const {
            if(dlogp < 0) {
                dlogp = this->logp;
            }

            Ciphertext res;
            this->scheme->modDownBy(res, const_cast<Ciphertext&>(this->cipher), dlogp);

            return Cipher(*this, std::move(res));
        }

        Cipher modDownInplace(double dlogp = -1) {
            if(dlogp < 0) {
                dlogp = this->logp;
            }

            this->scheme->modDownByAndEqual(this->cipher, dlogp);

            return *this;
        }

        Cipher operator +(const Cipher& rh) const {
                if (this->scheme != rh.scheme) {
                throw std::runtime_error("scheme mismatch");
            }

            Ciphertext res;
            this->scheme->add(res, const_cast<Ciphertext&>(this->cipher), const_cast<Ciphertext&>(rh.cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher operator +(double d) const {
            Ciphertext res;
            this->scheme->addConst(res, const_cast<Ciphertext&>(this->cipher), d, this->cipher.logp);

            return Cipher(*this, std::move(res));
        }

        Cipher operator *(const Cipher& rh) const {
            if (this->scheme != rh.scheme) {
                throw std::runtime_error("scheme mismatch");
            }

            Ciphertext res;
            this->scheme->mult(res, const_cast<Ciphertext&>(this->cipher), const_cast<Ciphertext&>(rh.cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher operator *(double d) const {
            Ciphertext res;
            this->scheme->multByConst(res, const_cast<Ciphertext&>(this->cipher), d, this->cipher.logp);

            return Cipher(*this, std::move(res));
        }

        Cipher& operator +=(const Cipher& rh) {
            if (this->scheme != rh.scheme) {
                throw std::runtime_error("scheme mismatch");
            }

            this->scheme->addAndEqual(this->cipher, const_cast<Ciphertext&>(rh.cipher));

            return *this;
        }

        Cipher& operator +=(double d) {
            this->scheme->addConstAndEqual(this->cipher, d, this->cipher.logp);

            return *this;
        }

        Cipher& operator *=(const Cipher& rh) {
            if (this->scheme != rh.scheme) {
                throw std::runtime_error("scheme mismatch");
            }

            this->scheme->multAndEqual(this->cipher, const_cast<Ciphertext&>(rh.cipher));

            return *this;
        }

        Cipher& operator *=(double d) {
            this->scheme->multByConstAndEqual(this->cipher, d, this->cipher.logp);

            return *this;
        }

        Cipher square() const {
            Ciphertext res;
            this->scheme->square(res, const_cast<Ciphertext&>(this->cipher));

            return Cipher(*this, std::move(res));
        }

        Cipher& squareInplace() {
            this->scheme->squareAndEqual(this->cipher);

            return *this;
        }

        Ciphertext& getCiphertext() {
            return this->cipher;
        }

        Ciphertext& operator ->() {
            return this->cipher;
        }
    };
}

#endif //HEAAN_TEST_CIPHER_HPP