//
// Created by Tsuzu on 2020/07/01.
//

#ifndef HEAAN_TEST_NAIVE_BAYES_HPP
#define HEAAN_TEST_NAIVE_BAYES_HPP

#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <sstream>
#include <numeric>
#include "cipher.hpp"
#include "crypyo.hpp"

namespace Bayes {
    struct Model {
        int class_num; //Number of classes
        int feature_num; //Number of features
        std::vector<int> feature_value_num; //Number of values per feature
        std::vector<std::vector<double> > probs;
    };

    struct Info {
        int class_num;
        int num_features;
        std::vector<std::string> class_names;
        std::vector<std::vector<std::string> > attr_values;
    };


    Model readModel(const std::string& filename, const std::vector<std::string>& class_names,
                    const std::vector<std::vector<std::string>>& attr_values) {
        Model NB;
        NB.class_num = class_names.size(); //Number of classes
        NB.feature_num = attr_values.size(); //Number of features
        //cout << "Number of features: " << NB.feature_num << endl;
        NB.feature_value_num; //Number of possible values per feature
        for (int i = 0; i < NB.feature_num; i++) {
            NB.feature_value_num.push_back(attr_values[i].size());
        } // array that contains number of possible values for each attribute

        std::ifstream infile(filename);

        if(!infile) {
            throw std::runtime_error("unknown file: " + filename);
        }
        std::string line;

        double num;
        int count = 0;
        int class_count = -1;

        while (getline(infile, line)) {
            std::stringstream ss(line);

            //Reads class probabilities into class_prob
            if (count == 0) {
                while (ss >> num) {
                    std::vector<double> temp;
                    temp.push_back(num);
                    NB.probs.push_back(temp);
                    if (ss.peek() == ',') { ss.ignore(); }
                }
            } else if (((NB.feature_num * class_count) + 2 + class_count <= count) &&
                       (count <= ((NB.feature_num * class_count) + 1 + class_count + NB.feature_num))) {
                while (ss >> num) {
                    NB.probs[class_count].push_back(num);
                    if (ss.peek() == ',') { ss.ignore(); }
                }
            } else { class_count += 1; }

            count += 1;
        }
        return NB;
    }

    Info readInfo(const std::string& filename) {
        Info info;

        std::ifstream infile(filename);

        if(!infile) {
            throw std::runtime_error("unknown file: " + filename);
        }
        std::string line;
        int count = 0;
        info.num_features = 0;

        while (getline(infile, line)) {
            std::stringstream ss(line);

            if (count == 0) {
                count++;
                while (ss.good()) {
                    std::string substr;
                    std::getline(ss, substr, ',');
                    info.class_names.push_back(substr);
                }
            } else {
                std::vector<std::string> temp;
                while (ss.good()) {
                    std::string substr;
                    getline(ss, substr, ',');
                    temp.push_back(substr);
                }
                info.num_features += temp.size();
                info.attr_values.push_back(temp);
            }
        }
        info.class_num = info.class_names.size();

        return info;
    }

    std::vector<EasyHEAAN::Cipher> encryptModel(const EasyHEAAN::Crypto& crypto, const Info& info, const Model& NB) {
        int num_slots = 1 << crypto.logn;
        int class_num = NB.class_num;
        int num_probs = info.num_features + 1;
        int num_data =  num_slots/num_probs;

        std::vector<EasyHEAAN::Cipher> res;
        res.reserve(class_num);
        for (int i=0; i<class_num; i++){
            vector <double> temp = NB.probs[i];
            for (int j=0; j<num_data-1; j++){
                temp.insert(temp.end(), NB.probs[i].begin(), NB.probs[i].end());
            }
            temp.resize(num_slots);

            auto c = crypto.encrypt(temp.begin(), temp.end(), num_slots);

            res.emplace_back(std::move(c));
        }

        return res;
    }

    std::vector<std::vector<std::string>> readData(const std::string& filename){
        std::vector <std::vector <std::string> > data;
        std::ifstream infile(filename);
        if(!infile) {
            throw std::runtime_error("unknown file: " + filename);
        }

        std::string line;

        while (std::getline(infile, line)){
            std::vector <std::string> temp;
            std::stringstream ss(line);
            std::string value;

            while (getline(ss, value, ',')){
                temp.push_back(value);
            }

            temp.pop_back(); //pops out the class label
            data.push_back(temp);
        }
        infile.close();
        return data;
    }

    std::vector<std::vector<double>> parseData(
            const std::vector<std::vector<std::string>>& data,
            const std::vector<std::vector<std::string>>& attr_values
    ) {
        std::vector<std::vector<double>> parsed;
        parsed.reserve(data.size());

        auto len = std::accumulate(
                attr_values.begin(),
                attr_values.end(),
                0,
                [](auto&& l, auto&& r) {
                    return l + r.size();
                }
            );

        for(auto&& d : data) {
            std::vector<double> r;
            r.reserve(len + 1);

            r.push_back(1);
            for (int i =0; i < d.size(); i++){
                for (int j=0; j < attr_values[i].size(); j++){
                    if (d[i] == attr_values[i][j]){ r.push_back(1); }
                    else { r.push_back(0); }
                }
            }

            parsed.emplace_back(r);
        }

        return parsed;
    }
}

#endif //HEAAN_TEST_NAIVE_BAYES_HPP
