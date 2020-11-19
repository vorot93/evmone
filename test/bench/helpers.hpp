// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "test/utils/utils.hpp"
#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>
#include <evmone/analysis.hpp>

namespace evmone::test
{
extern std::map<std::string_view, evmc::VM> registered_vms;

constexpr auto gas_limit = std::numeric_limits<int64_t>::max();

inline void analyse(benchmark::State& state, bytes_view code) noexcept
{
    auto bytes_analysed = uint64_t{0};
    for (auto _ : state)
    {
        auto r = evmone::analyze(EVMC_ISTANBUL, code.data(), code.size());
        benchmark::DoNotOptimize(r);
        bytes_analysed += code.size();
    }

    using benchmark::Counter;
    state.counters["size"] = Counter(static_cast<double>(code.size()));
    state.counters["rate"] = Counter(static_cast<double>(bytes_analysed), Counter::kIsRate);
}

inline evmc::result execute(evmc::VM& vm, bytes_view code, bytes_view input) noexcept
{
    auto msg = evmc_message{};
    msg.gas = gas_limit;
    msg.input_data = input.data();
    msg.input_size = input.size();
    return vm.execute(EVMC_ISTANBUL, msg, code.data(), code.size());
}

inline void execute(benchmark::State& state, evmc::VM& vm, bytes_view code, bytes_view input = {},
    bytes_view expected_output = {}) noexcept
{
    {  // Test run.
        const auto r = execute(vm, code, input);
        if (r.status_code != EVMC_SUCCESS)
        {
            state.SkipWithError(("failure: " + std::to_string(r.status_code)).c_str());
            return;
        }

        if (!expected_output.empty())
        {
            const auto output = bytes_view{r.output_data, r.output_size};
            if (output != expected_output)
            {
                auto error = "got: " + hex(output) + "  expected: " + hex(expected_output);
                state.SkipWithError(error.c_str());
                return;
            }
        }
    }

    auto total_gas_used = int64_t{0};
    auto iteration_gas_used = int64_t{0};
    for (auto _ : state)
    {
        auto r = execute(vm, code, input);
        iteration_gas_used = gas_limit - r.gas_left;
        total_gas_used += iteration_gas_used;
    }

    using benchmark::Counter;
    state.counters["gas_used"] = Counter(static_cast<double>(iteration_gas_used));
    state.counters["gas_rate"] = Counter(static_cast<double>(total_gas_used), Counter::kIsRate);
}
}  // namespace evmone::test
