#include <filesystem>
#include <HEAAN.h>
#include "compare.hpp"
#include "crypyo.hpp"
#include "naive_bayes.hpp"

//using namespace std;
//using namespace NTL;
//
//int main3(int argc, char** argv) {
//    long logq = 1200; ///< Ciphertext Modulus
//    long logp = 30; ///< Real message will be quantized by multiplying 2^40
//    long logn = 5; ///< log2(The number of slots)
//    argv[1] = "Bootstrapping";
//
////----------------------------------------------------------------------------------
////   STANDARD TESTS
////----------------------------------------------------------------------------------
//
//    if(string(argv[1]) == "Encrypt") TestScheme::testEncrypt(logq, logp, logn);
//    if(string(argv[1]) == "EncryptSingle") TestScheme::testEncryptSingle(logq, logp);
//    if(string(argv[1]) == "Add") TestScheme::testAdd(logq, logp, logn);
//    if(string(argv[1]) == "Mult") TestScheme::testMult(logq, logp, logn);
//    if(string(argv[1]) == "iMult") TestScheme::testiMult(logq, logp, logn);
//
////----------------------------------------------------------------------------------
////   ROTATE & CONJUGATE
////----------------------------------------------------------------------------------
//
//    long r = 1; ///< The amout of rotation
//    if(string(argv[1]) == "RotateFast") TestScheme::testRotateFast(logq, logp, logn, r);
//    if(string(argv[1]) == "Conjugate") TestScheme::testConjugate(logq, logp, logn);
//
////----------------------------------------------------------------------------------
////   BOOTSTRAPPING
////----------------------------------------------------------------------------------
//
//    logq = logp + 10; //< suppose the input ciphertext of bootstrapping has logq = logp + 10
//    logn = 3; //< larger logn will make bootstrapping tech much slower
//    long logT = 4; //< this means that we use Taylor approximation in [-1/T,1/T] with double angle fomula
//    if(string(argv[1]) == "Bootstrapping") TestScheme::testBootstrap(logq, logp, logn, logT);
//
//    return 0;
//
//}
//
//std::ostream& operator << (std::ostream& os, EasyHEAAN::Cipher& c) {
//    os << "logp: " << c.getCiphertext().logp
//       << ", logq: " << c.getCiphertext().logq
//       << ", n: " << c.getCiphertext().n;
//
//    return os;
//}
//

std::ostream& operator << (std::ostream& os, const std::vector<double>& vec) {
    os << "[";
    for(auto && v : vec) {
        os << v << ", ";
    }
    os << "]";

    return os;
}

int main() {
    long logq = 1200; ///< Ciphertext modulus (this value should be <= logQ in "scr/Params.h")
    long logp = 30; ///< Scaling Factor (larger logp will give you more accurate value)
    long logn = 6; ///< number of slot is 1024 (this value should be < logN in "src/Params.h")
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

    auto crypto = EasyHEAAN::Crypto(scheme, logp, logq, logn);
    EasyHEAAN::Bootstrapper bs;
    bs.logq = logp + 10;
    bs.logQ = logQ;

    scheme->addBootKey(secretKey, logn, bs.logq + bs.logI);
    scheme->addLeftRotKeys(secretKey);
//    scheme->addRightRotKeys(secretKey);

    crypto.useSecretKey(secretKey);
    crypto.setupBootstrapping(bs);

    std::cout << "key generation finished" << std::endl;

    auto info = Bayes::readInfo("../datasets/sample22_info.csv");
    auto NB = Bayes::readModel("../datasets/sample22_model.csv", info.class_names, info.attr_values);
    std::cout << "info: " << info.class_num << std::endl;

    auto model_ctxts = Bayes::encryptModel(
            crypto, info, NB
            );

    auto data = Bayes::parseData(
            Bayes::readData("../datasets/sample22_50_test.csv"),
            info.attr_values
            );
    std::cout << "info: " << data.size() << std::endl;

    for(auto&& d : data) {
        using std::chrono::system_clock;
        auto p = system_clock::now();
        auto ct_data = crypto.encrypt(d.begin(), d.end(), n);

        std::vector <EasyHEAAN::Cipher> res_ctxts;
        res_ctxts.reserve(info.class_num);
        for (int j = 0; j<info.class_num; j++){
            auto res = model_ctxts[j];
            res *= ct_data;
            res.rescaleByInplace();

            res = res.sumAll();
            res /= 50;
            res.rescaleByInplace();
            res += 0.5;

            res_ctxts.emplace_back(res);
        }

        for(auto&& c : crypto.decrypt(res_ctxts)) {
            std::cout << c << std::endl;
        }

        auto res = CKKSCompare::maxIdx(res_ctxts, 10, 10, 5, 10);

        for(auto&& c : crypto.decrypt(res)) {
            std::cout << c << std::endl;
        }

        std::cout << CKKSCompare::getMaxIdx(crypto.decrypt(res)) << std::endl;

        auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(system_clock::now()-p).count();;
        std::cout <<  dur << "ms" << std::endl;
    }
}

int main4() {
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

    auto crypto = EasyHEAAN::Crypto(scheme, logp, logq, logn);
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

//    auto cph = crypto.encrypt({1,2,4}, n, 1);
//
//    while(cph.getCiphertext().logq > logp*2) {
//        cph.modDownInplace();
//    }
//
//    for(auto&& v : crypto.decrypt(cph)) {
//        std::cout << v << std::endl;
//    }
//
//    std::cout << cph.getCiphertext().logq << std::endl;
//    std::cout << cph.getCiphertext().logp << std::endl;
//
//    cph.bootstrapInplace();
//
//    std::cout << cph.getCiphertext().logq << std::endl;
//    std::cout << cph.getCiphertext().logp << std::endl;
//
//    for(auto&& v : crypto.decrypt(cph)) {
//        std::cout << v << std::endl;
//    }
//
//    return 0;

    auto debugPrint = [&](const EasyHEAAN::Cipher& c) {
        for(auto&& v : crypto.decrypt(c)) {
            std::cout << v << ", ";
        }
        std::cout << std::endl;
    };

    auto debugPrintArray = [&](const std::vector<EasyHEAAN::Cipher>& arr) {
        std::cout << "[" << std::endl;
        for(auto&& c : arr) {
            std::cout << "    ";
            debugPrint(c);
        }
        std::cout << "]" << std::endl;
    };

    const auto maxIdx = [&debugPrint, &debugPrintArray](const std::vector<EasyHEAAN::Cipher>& a, int d, int d_, int m, int t) {
        std::cout << "logQ" << a[0].getCiphertext().logq << std::endl;
        debugPrintArray(a);

        auto inv = ::CKKSCompare::inv(
                (CKKSCompare::sum(a) / a.size()).rescaleByInplace(),
                d_
        );
        // (d_ + 1) + 1

        debugPrint(inv);

        std::cout << "logQ" << inv.getCiphertext().logq << std::endl;

        std::vector<EasyHEAAN::Cipher> b;
        b.reserve(a.size());
        for(int i = 0; i < a.size() - 1; ++i) {
            auto ai = a[i].modDownTo(inv);
            ai *= inv;
            ai.rescaleByInplace();
            ai /= a.size();
            ai.rescaleByInplace();
            b.emplace_back(std::move(ai));
        }
        b.emplace_back(-CKKSCompare::sum(b)+1);
        // 2

        debugPrintArray(b);

        std::cout << b[0].getCiphertext().logq << std::endl;

        const int levelDown = static_cast<int>(std::log2(m)) + d + 2;
        for(int i = 0; i < t; ++i) {
            if ((levelDown + 1) * b[0].getCiphertext().logp > b[0].getCiphertext().logq) {
                for(auto& c : b) {
                    c.bootstrapInplace();
                }
            }

            for(auto& c : b) {
                debugPrint(c);
                c = c.pow(m);
                debugPrint(c);
            }
            // floor(log m)

            auto inv = ::CKKSCompare::inv(CKKSCompare::sum(b), d);
            // d + 1
            debugPrint(inv);

            for(int j = 0; j < b.size() - 1; ++j) {
                b[j].modDownToInplace(inv);
                b[j] *= inv;
                b[j].rescaleByInplace();
            }
            // 1

            b[b.size() - 1] = -CKKSCompare::sum(b.begin(), std::prev(b.end())) + 1;

            std::cout << b[0].getCiphertext().logq << std::endl;
            debugPrintArray(b);
        }

        return b;
    };

    auto res = maxIdx({
       crypto.encrypt({0.6,0.9,1.3}, n, 1),
        crypto.encrypt({1.2,0.5,0.6}, n, 1),
    }, 10, 10, 4, 5);

    std::cout << "encrypted" << std::endl;

    for(auto&& c : res) {
        for (auto &&v : crypto.decrypt(c)) {
            std::cout << v << std::endl;
        }
    }

    return 0;

    auto d = 5;

//    auto inv = CKKSCompare::sqrt(cph, d);
//
//    std::cout << "inversed" << std::endl;
//
//    for(auto&& v: crypto.decrypt(inv)) {
//        std::cout << v << std::endl;
//    }
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
