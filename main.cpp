#include <HEAAN.h>
#include "compare.hpp"
#include "crypyo.hpp"

using namespace std;
using namespace NTL;

int main3(int argc, char** argv) {
    long logq = 1200; ///< Ciphertext Modulus
    long logp = 30; ///< Real message will be quantized by multiplying 2^40
    long logn = 5; ///< log2(The number of slots)
    argv[1] = "Bootstrapping";

//----------------------------------------------------------------------------------
//   STANDARD TESTS
//----------------------------------------------------------------------------------

    if(string(argv[1]) == "Encrypt") TestScheme::testEncrypt(logq, logp, logn);
    if(string(argv[1]) == "EncryptSingle") TestScheme::testEncryptSingle(logq, logp);
    if(string(argv[1]) == "Add") TestScheme::testAdd(logq, logp, logn);
    if(string(argv[1]) == "Mult") TestScheme::testMult(logq, logp, logn);
    if(string(argv[1]) == "iMult") TestScheme::testiMult(logq, logp, logn);

//----------------------------------------------------------------------------------
//   ROTATE & CONJUGATE
//----------------------------------------------------------------------------------

    long r = 1; ///< The amout of rotation
    if(string(argv[1]) == "RotateFast") TestScheme::testRotateFast(logq, logp, logn, r);
    if(string(argv[1]) == "Conjugate") TestScheme::testConjugate(logq, logp, logn);

//----------------------------------------------------------------------------------
//   BOOTSTRAPPING
//----------------------------------------------------------------------------------

    logq = logp + 10; //< suppose the input ciphertext of bootstrapping has logq = logp + 10
    logn = 3; //< larger logn will make bootstrapping tech much slower
    long logT = 4; //< this means that we use Taylor approximation in [-1/T,1/T] with double angle fomula
    if(string(argv[1]) == "Bootstrapping") TestScheme::testBootstrap(logq, logp, logn, logT);

    return 0;

}

std::ostream& operator << (std::ostream& os, EasyHEAAN::Cipher& c) {
    os << "logp: " << c.getCiphertext().logp
       << ", logq: " << c.getCiphertext().logq
       << ", n: " << c.getCiphertext().n;

    return os;
}


int main() {
    long logq = 1200; ///< Ciphertext modulus (this value should be <= logQ in "scr/Params.h")
    long logp = 30; ///< Scaling Factor (larger logp will give you more accurate value)
    long logn = 3; ///< number of slot is 1024 (this value should be < logN in "src/Params.h")
    long n = 1 << logn;
    long slots = n;
    long numThread = 6;

    // Construct and Generate Public Keys //
    srand(time(NULL));
    SetNumThreads(numThread);
    TimeUtils timeutils;
    Ring ring;
    SecretKey secretKey(ring);
    auto scheme = std::make_shared<Scheme>(secretKey, ring);
//    scheme->addLeftRotKeys(secretKey); ///< When you need left rotation for the vectorized message
//    scheme->addRightRotKeys(secretKey); ///< When you need right rotation for the vectorized message

    std::cout << "key generation finished" << std::endl;

    auto crypto = EasyHEAAN::Crypto(scheme, logp, logq);
    EasyHEAAN::Bootstrapper bs;
    bs.logq = logp + 10;
    bs.logQ = logQ;

    scheme->addBootKey(secretKey, logn, bs.logq + bs.logI);

    crypto.useSecretKey(secretKey);
    crypto.setupBootstrapping(bs);

    auto debug = [&](const EasyHEAAN::Cipher& c) {
        auto v = crypto.decrypt(c);

        for (int i = 0; i < 3; ++i) {
            std::cout << v[i] << ", ";
        }
        std::cout << std::endl;
    };

    auto cph = crypto.encrypt({1,2,4}, n, 1);

    while(cph.getCiphertext().logq > logp*2) {
        cph.modDownInplace();
    }

    for(auto&& v : crypto.decrypt(cph)) {
        std::cout << v << std::endl;
    }

    std::cout << cph.getCiphertext().logq << std::endl;
    std::cout << cph.getCiphertext().logp << std::endl;

    cph.bootstrapInplace();

    std::cout << cph.getCiphertext().logq << std::endl;
    std::cout << cph.getCiphertext().logp << std::endl;

    for(auto&& v : crypto.decrypt(cph)) {
        std::cout << v << std::endl;
    }

    return 0;

    auto res = CKKSCompare::maxIdx({
       crypto.encrypt({0.6,0.9,1.3}, n, 1),
        crypto.encrypt({1.2,0.5,0.4}, n, 1),
    }, 5, 5, 5, 5);

    std::cout << "encrypted" << std::endl;

    for(auto&& v : crypto.decrypt(res[0])) {
        std::cout << v << std::endl;
    }
    return 0;

    auto d = 5;

    auto inv = CKKSCompare::sqrt(cph, d);

    std::cout << "inversed" << std::endl;

    for(auto&& v: crypto.decrypt(inv)) {
        std::cout << v << std::endl;
    }
}

int main2() {
    /*
    * Basic Parameters are in src/Params.h
    * If you want to use another parameter, you need to change src/Params.h file and re-complie this library.
    */

    // Parameters //
    long logq = 300; ///< Ciphertext modulus (this value should be <= logQ in "scr/Params.h")
    long logp = 30; ///< Scaling Factor (larger logp will give you more accurate value)
    long logn = 10; ///< number of slot is 1024 (this value should be < logN in "src/Params.h")
    long n = 1 << logn;
    long slots = n;
    long numThread = 8;

    // Construct and Generate Public Keys //
    srand(time(NULL));
    SetNumThreads(numThread);
    TimeUtils timeutils;
    Ring ring;
    SecretKey secretKey(ring);
    Scheme scheme(secretKey, ring);
    scheme.addLeftRotKeys(secretKey); ///< When you need left rotation for the vectorized message
    scheme.addRightRotKeys(secretKey); ///< When you need right rotation for the vectorized message

    // Make Random Array of Complex //
    complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(slots);
    complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(slots);

    // Encrypt Two Arry of Complex //
    Ciphertext cipher1;
    scheme.encrypt(cipher1, mvec1, n, logp, logq);
    Ciphertext cipher2;
    scheme.encrypt(cipher2, mvec2, n, logp, logq);

    // Addition //
    Ciphertext cipherAdd;
    scheme.add(cipherAdd, cipher1, cipher2);

    // Multiplication And Rescale //
    Ciphertext cipherMult;
    scheme.mult(cipherMult, cipher1, cipher2);
    Ciphertext cipherMultAfterReScale;
    scheme.reScaleBy(cipherMultAfterReScale, cipherMult, logp);

    // Rotation //
    long idx = 1;
    Ciphertext cipherRot;
    scheme.leftRotateFast(cipherRot, cipher1, idx);

    // Decrypt //
    complex<double>* dvec1 = scheme.decrypt(secretKey, cipher1);
    complex<double>* dvec2 = scheme.decrypt(secretKey, cipher2);

    return 0;
}
