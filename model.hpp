//
// Created by Tsuzu on 2020/07/01.
//

#ifndef HEAAN_TEST_MODEL_HPP
#define HEAAN_TEST_MODEL_HPP

#include <vector>
#include <string>
#include <fstream>
#include <sstream>

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


    Model readModel(std::string filename, std::vector<std::string> class_names,
                    std::vector<std::vector<std::string> > attr_values) {
        Model NB;
        NB.class_num = class_names.size(); //Number of classes
        NB.feature_num = attr_values.size(); //Number of features
        //cout << "Number of features: " << NB.feature_num << endl;
        NB.feature_value_num; //Number of possible values per feature
        for (int i = 0; i < NB.feature_num; i++) {
            NB.feature_value_num.push_back(attr_values[i].size());
        } // array that contains number of possible values for each attribute

        std::ifstream infile(filename);
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

    Info readInfo(std::string filename) {
        Info info;

        std::ifstream infile(filename);
        std::string line;
        int count = 0;
        info.num_features = 0;

        while (getline(infile, line)) {
            std::stringstream ss(line);

            if (count == 0) {
                count++;
                while (ss.good()) {
                    std::string substr;
                    getline(ss, substr, ',');
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
}

#endif //HEAAN_TEST_MODEL_HPP
