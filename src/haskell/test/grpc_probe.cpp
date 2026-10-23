// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/bridge.h>
#include <chrono>
#include <exception>
#include <iostream>
#include <thread>

int main(int argc, char** argv)
{
    if (argc != 6) return 2;
    const std::string directory{argv[2]}, mode{argv[5]};
    const auto start = std::chrono::steady_clock::now();
    const auto request = [&] {
        drivechain::haskell::GrpcResponse result;
        // Match the node's C++ -> Haskell -> C++ callback -> Haskell transport path.
        drivechain::haskell::ParentReplayAll<2>({[] { return true; }, [&] {
            result = drivechain::haskell::GrpcRequest(std::array<std::string,7>{
                argv[3], argv[4], argv[1], directory + "/ca.pem",
                directory + "/elements-client.pem", directory + "/elements-client-key.pem",
                mode == "wrong-authority" ? "wrong.invalid" : "enforcer.local"},
                mode == "deadline" ? 100 : 2000, 65536, [&] {
                    return mode == "cancel" && std::chrono::steady_clock::now() - start > std::chrono::milliseconds{100};
                });
            return true;
        }});
        return result;
    };
    drivechain::haskell::GrpcResponse result;
    if (mode == "concurrent") {
        std::array<drivechain::haskell::GrpcResponse, 8> results;
        std::array<std::exception_ptr, 8> failures{};
        std::array<std::thread, 8> workers;
        for (size_t i = 0; i < workers.size(); ++i) workers[i] = std::thread([&, i] {
            try { results[i] = request(); }
            catch (...) { failures[i] = std::current_exception(); }
        });
        for (auto& worker : workers) worker.join();
        for (size_t i = 0; i < results.size(); ++i) {
            if (failures[i] || results[i].status != results[0].status ||
                results[i].output != results[0].output) return 1;
        }
        result = std::move(results[0]);
    } else {
        result = request();
        if (mode == "repeat") for (unsigned i = 1; i < 4; ++i) {
            const auto next = request();
            if (next.status != result.status || next.output != result.output) return 1;
        }
    }
    std::cout << result.status << '\n' << result.output << '\n';
    return 0;
}
