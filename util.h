//
// Created by Jessica Miller on 3/23/25.
//

#ifndef UTIL_H
#define UTIL_H



#include <vector>
#include <cstdint>

const int ITERATIONS = 1000;

extern std::vector<int64_t> sign_times;
extern std::vector<int64_t> verify_times;
extern std::vector<int64_t> sign_cpu_usgage;
extern std::vector<int64_t> verify_cpu_usgage;
extern std::vector<int64_t> keygen_times;

void get_average_sign_time(unsigned long long &average_sign_time, std::vector<int64_t> &sign_times);
void get_average_sign_cpu_time(unsigned long long &average_cpu_time, std::vector<int64_t> &cpu_times);
void get_average_keygen_time(unsigned long long &average_key_time, std::vector<int64_t> &keygen_times);
void get_average_verify_time(unsigned long long &average_verify_time, std::vector<int64_t> &verify_times);
void get_average_verify_cpu_time(unsigned long long &average_cpu_time, std::vector<int64_t> &cpu_times);
void get_stddev_sign(unsigned long long &stddev_sign_time, std::vector<int64_t> &sign_times);
void get_stddev_verify(unsigned long long &stddev_verify_time, std::vector<int64_t> &verify_times);

void record_results(unsigned long long average_key_time,
                    unsigned long long average_sign_time,
                    unsigned long long average_sign_cpu,
                    unsigned long long average_verify_time,
                    unsigned long long average_verify_cpu,
                    unsigned long long stddev_sign_time,
                    unsigned long long stddev_verify_time,
                    std::ostream& out);


#endif