//
// Created by Jessica Miller on 3/23/25.
//


#include <cstdint>
#include <vector>
#include <numeric>
#include <cmath>
#include <fstream>
#include <iostream>
#include "util.h"
size_t current_message_len = 2500;

std::vector<int64_t> sign_times;
std::vector<int64_t> verify_times;
std::vector<int64_t> sign_cpu_usgage;
std::vector<int64_t> verify_cpu_usgage;
std::vector<int64_t> keygen_times;

void get_average_sign_time(unsigned long long &average_sign_time, std::vector<int64_t> &sign_times) {

    uint64_t total = 0;
    for(int64_t i : sign_times)
        total += i;
    average_sign_time = total / sign_times.size();
}

void get_average_keygen_time(unsigned long long &average_key_time, std::vector<int64_t> &keygen_times) {

    uint64_t total = 0;
    for(int64_t i : keygen_times)
        total += i;
    average_key_time = total / keygen_times.size();
}
void get_average_sign_cpu_time(unsigned long long &average_cpu_time, std::vector<int64_t> &cpu_times) {

    uint64_t total = 0;
    for(int64_t i : cpu_times)
        total += i;
    average_cpu_time = total / cpu_times.size();
}

void get_average_verify_cpu_time(unsigned long long &average_verify_time, std::vector<int64_t> &verify_times) {

    uint64_t total = 0;
    for(int64_t i : verify_times)
        total += i;
    average_verify_time = total / verify_times.size();
}

void get_average_verify_time(unsigned long long &average_verify_time, std::vector<int64_t> &verify_times) {

    uint64_t total = 0;
    for(int64_t i : verify_times)
        total += i;
    average_verify_time = total / verify_times.size();
}

void get_stddev_sign(unsigned long long &stddev_sign_time, std::vector<int64_t> &sign_times) {
    double sum = std::accumulate(sign_times.begin(), sign_times.end(), 0.0);
    double mean = sum / sign_times.size();
    double squared_sum = std::inner_product(sign_times.begin(), sign_times.end(), sign_times.begin(), 0.0);
    stddev_sign_time = std::sqrt(squared_sum / sign_times.size() - mean * mean);
}

void get_stddev_verify(unsigned long long &stddev_verify_time, std::vector<int64_t> &verify_times) {
    double sum = std::accumulate(verify_times.begin(), verify_times.end(), 0.0);
    double mean = sum / verify_times.size();
    double squared_sum = std::inner_product(verify_times.begin(), verify_times.end(), verify_times.begin(), 0.0);
    stddev_verify_time = std::sqrt(squared_sum / verify_times.size() - mean * mean);
}

void record_results(unsigned long long average_key_time,
                    unsigned long long average_sign_time,
                    unsigned long long average_sign_cpu,
                    unsigned long long average_verify_time,
                    unsigned long long average_verify_cpu,
                    unsigned long long stddev_sign_time,
                    unsigned long long stddev_verify_time,
                    std::ostream& out) {
    out << "Average key generation time (ns):\t\t" << average_key_time / 1'000'000.0 << "\n";

    out << "Average sign time (ns):\t\t" << average_sign_time / 1'000'000.0<< "\n";
    out << "Average verify cpu (ns):\t" << average_sign_cpu / 1'000'000.0<< "\n";
    out << "Std. sign time (ns):\t\t" << stddev_sign_time / 1'000'000.0<< "\n\n";

    out << "Average verify time (ns):\t" << average_verify_time / 1'000'000.0 << "\n";
    out << "Average verify cpu (ns):\t" << average_verify_cpu / 1'000'000.0<< "\n";
    out << "Std. verify time (ns):\t\t" << stddev_verify_time / 1'000'000.0<< "\n";

}