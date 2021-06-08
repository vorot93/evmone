// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "baseline_instruction_table.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include "vm.hpp"
#include <evmc/instructions.h>
#include <memory>

namespace evmone::baseline
{
CodeAnalysis analyze(const uint8_t* code, size_t code_size)
{
    // To find if op is any PUSH opcode (OP_PUSH1 <= op <= OP_PUSH32)
    // it can be noticed that OP_PUSH32 is INT8_MAX (0x7f) therefore
    // static_cast<int8_t>(op) <= OP_PUSH32 is always true and can be skipped.
    static_assert(OP_PUSH32 == std::numeric_limits<int8_t>::max());

    CodeAnalysis::JumpdestMap map(code_size);  // Allocate and init bitmap with zeros.
    size_t i = 0;
    while (i < code_size)
    {
        const auto op = code[i];
        if (static_cast<int8_t>(op) >= OP_PUSH1)  // If any PUSH opcode (see explanation above).
            i += op - size_t{OP_PUSH1 - 1};       // Skip PUSH data.
        else if (INTX_UNLIKELY(op == OP_JUMPDEST))
            map[i] = true;
        ++i;
    }

    // i is the needed code size including the last push data (can be bigger than code_size).
    // Using "raw" new operator instead of std::make_unique() to get uninitialized array.
    std::unique_ptr<uint8_t[]> padded_code{new uint8_t[i + 1]};  // +1 for the final STOP.
    std::copy_n(code, code_size, padded_code.get());
    padded_code[i] = OP_STOP;  // Set final STOP at the code end.

    // TODO: Using fixed-size padding of 33, the padded code buffer and jumpdest bitmap can be
    //       created with single allocation.

    return CodeAnalysis{std::move(padded_code), std::move(map)};
}

namespace
{
const uint8_t* op_jump(
    ExecutionState& state, const CodeAnalysis::JumpdestMap& jumpdest_map) noexcept
{
    const auto dst = state.stack.pop();
    if (dst >= jumpdest_map.size() || !jumpdest_map[static_cast<size_t>(dst)])
    {
        state.status = EVMC_BAD_JUMP_DESTINATION;
        return &state.code[0] + state.code.size();
    }

    return &state.code[static_cast<size_t>(dst)];
}

template <size_t Len>
inline const uint8_t* load_push(ExecutionState& state, const uint8_t* code) noexcept
{
    uint8_t buffer[Len];
    // This valid because code is padded with garbage to satisfy push data read pass the code end.
    std::memcpy(buffer, code, Len);
    state.stack.push(intx::be::load<intx::uint256>(buffer));
    return code + Len;
}

template <evmc_status_code StatusCode>
inline void op_return(ExecutionState& state) noexcept
{
    const auto offset = state.stack[0];
    const auto size = state.stack[1];

    if (!check_memory(state, offset, size))
    {
        state.status = EVMC_OUT_OF_GAS;
        return;
    }

    state.output_offset = static_cast<size_t>(offset);  // Can be garbage if size is 0.
    state.output_size = static_cast<size_t>(size);
    state.status = StatusCode;
}

inline evmc_status_code check_requirements(
    const InstructionTable& instruction_table, ExecutionState& state, uint8_t op) noexcept
{
    const auto metrics = instruction_table[op];

    const auto gas_cost = int64_t{metrics.gas_cost} & 0x7fffffffffffffff;
    if (INTX_UNLIKELY((state.gas_left -= gas_cost) < 0))
        return gas_cost == 0x7fffffffffffffff ? EVMC_UNDEFINED_INSTRUCTION : EVMC_OUT_OF_GAS;

    const auto stack_size = state.stack.size();
    if (INTX_UNLIKELY(stack_size < metrics.stack_height_required))
        return EVMC_STACK_UNDERFLOW;

    return EVMC_SUCCESS;
}

template <size_t N>
inline auto log_(ExecutionState& state)
{
    return log(state, N);
}

inline evmc_status_code wrap(void (*f)(Stack&), ExecutionState& state)
{
    f(state.stack);
    return EVMC_SUCCESS;
}

inline evmc_status_code wrap(void (*f)(ExecutionState&), ExecutionState& state)
{
    f(state);
    return EVMC_SUCCESS;
}

inline evmc_status_code wrap(evmc_status_code (*f)(ExecutionState&), ExecutionState& state)
{
    return f(state);
}

#define ADD_impl add
#define MUL_impl mul
#define SUB_impl sub

#define STOP_impl stop
#define ADD_impl add
#define MUL_impl mul
#define SUB_impl sub
#define DIV_impl div
#define SDIV_impl sdiv
#define MOD_impl mod
#define SMOD_impl smod
#define ADDMOD_impl addmod
#define MULMOD_impl mulmod
#define EXP_impl exp
#define SIGNEXTEND_impl signextend

#define LT_impl lt
#define GT_impl gt
#define SLT_impl slt
#define SGT_impl sgt
#define EQ_impl eq
#define ISZERO_impl iszero
#define AND_impl and_
#define OR_impl or_
#define XOR_impl xor_
#define NOT_impl not_
#define BYTE_impl byte
#define SHL_impl shl
#define SHR_impl shr
#define SAR_impl sar

#define KECCAK256_impl keccak256

#define ADDRESS_impl address
#define BALANCE_impl balance
#define ORIGIN_impl origin
#define CALLER_impl caller
#define CALLVALUE_impl callvalue
#define CALLDATALOAD_impl calldataload
#define CALLDATASIZE_impl calldatasize
#define CALLDATACOPY_impl calldatacopy
#define CODESIZE_impl codesize
#define CODECOPY_impl codecopy
#define GASPRICE_impl gasprice
#define EXTCODESIZE_impl extcodesize
#define EXTCODECOPY_impl extcodecopy
#define RETURNDATASIZE_impl returndatasize
#define RETURNDATACOPY_impl returndatacopy
#define EXTCODEHASH_impl extcodehash

#define BLOCKHASH_impl blockhash
#define COINBASE_impl coinbase
#define TIMESTAMP_impl timestamp
#define NUMBER_impl number
#define DIFFICULTY_impl difficulty
#define GASLIMIT_impl gaslimit
#define CHAINID_impl chainid
#define SELFBALANCE_impl selfbalance
#define BASEFEE_impl basefee

#define POP_impl pop
#define MLOAD_impl mload
#define MSTORE_impl mstore
#define MSTORE8_impl mstore8
#define SLOAD_impl sload
#define SSTORE_impl sstore
#define JUMP_impl jump
#define JUMPI_impl jumpi
#define PC_impl pc
#define MSIZE_impl msize
#define GAS_impl gas
#define JUMPDEST_impl jumpdest

#define PUSH1_impl push1
#define PUSH2_impl push2
#define PUSH3_impl push3
#define PUSH4_impl push4
#define PUSH5_impl push5
#define PUSH6_impl push6
#define PUSH7_impl push7
#define PUSH8_impl push8
#define PUSH9_impl push9
#define PUSH10_impl push10
#define PUSH11_impl push11
#define PUSH12_impl push12
#define PUSH13_impl push13
#define PUSH14_impl push14
#define PUSH15_impl push15
#define PUSH16_impl push16
#define PUSH17_impl push17
#define PUSH18_impl push18
#define PUSH19_impl push19
#define PUSH20_impl push20
#define PUSH21_impl push21
#define PUSH22_impl push22
#define PUSH23_impl push23
#define PUSH24_impl push24
#define PUSH25_impl push25
#define PUSH26_impl push26
#define PUSH27_impl push27
#define PUSH28_impl push28
#define PUSH29_impl push29
#define PUSH30_impl push30
#define PUSH31_impl push31
#define PUSH32_impl push32
#define DUP1_impl dup<1>
#define DUP2_impl dup<2>
#define DUP3_impl dup<3>
#define DUP4_impl dup<4>
#define DUP5_impl dup<5>
#define DUP6_impl dup<6>
#define DUP7_impl dup<7>
#define DUP8_impl dup<8>
#define DUP9_impl dup<9>
#define DUP10_impl dup<10>
#define DUP11_impl dup<11>
#define DUP12_impl dup<12>
#define DUP13_impl dup<13>
#define DUP14_impl dup<14>
#define DUP15_impl dup<15>
#define DUP16_impl dup<16>
#define SWAP1_impl swap<1>
#define SWAP2_impl swap<2>
#define SWAP3_impl swap<3>
#define SWAP4_impl swap<4>
#define SWAP5_impl swap<5>
#define SWAP6_impl swap<6>
#define SWAP7_impl swap<7>
#define SWAP8_impl swap<8>
#define SWAP9_impl swap<9>
#define SWAP10_impl swap<10>
#define SWAP11_impl swap<11>
#define SWAP12_impl swap<12>
#define SWAP13_impl swap<13>
#define SWAP14_impl swap<14>
#define SWAP15_impl swap<15>
#define SWAP16_impl swap<16>
#define LOG0_impl log_<0>
#define LOG1_impl log_<1>
#define LOG2_impl log_<2>
#define LOG3_impl log_<3>
#define LOG4_impl log_<4>

#define CREATE_impl create<EVMC_CREATE>
#define CALL_impl call<EVMC_CALL>
#define CALLCODE_impl call<EVMC_CALLCODE>
#define RETURN_impl return
#define DELEGATECALL_impl call<EVMC_DELEGATECALL>
#define CREATE2_impl create<EVMC_CREATE2>

#define STATICCALL_impl call<EVMC_CALL, true>

#define REVERT_impl revert
#define INVALID_impl invalid
#define SELFDESTRUCT_impl selfdestruct

#define CHECK_STACK_OVERFLOW(INSTR)                                  \
    if constexpr (instr::traits[OP_##INSTR].stack_height_change > 0) \
    {                                                                \
        if (state.stack.size() == Stack::limit)                      \
        {                                                            \
            state.status = EVMC_STACK_OVERFLOW;                      \
            goto exit;                                               \
        }                                                            \
    }

#define CASE(INSTR)                                         \
    case OP_##INSTR:                                        \
    {                                                       \
        CHECK_STACK_OVERFLOW(INSTR)                         \
        const auto status_code = wrap(INSTR##_impl, state); \
        if (status_code != EVMC_SUCCESS)                    \
        {                                                   \
            state.status = status_code;                     \
            goto exit;                                      \
        }                                                   \
        break;                                              \
    }

#define CASE_PUSH(N)                      \
    case OP_PUSH##N:                      \
    {                                     \
        CHECK_STACK_OVERFLOW(PUSH##N)     \
        pc = load_push<N>(state, pc + 1); \
        continue;                         \
    }


template <bool TracingEnabled>
evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    assert(state.gas_left < 0x7fffffffffffffff);

    // Use padded code.
    state.code = {analysis.padded_code.get(), state.code.size()};

    auto* tracer = vm.get_tracer();
    if constexpr (TracingEnabled)
        tracer->notify_execution_start(state.rev, *state.msg, state.code);

    const auto& instruction_table = get_baseline_instruction_table(state.rev);

    const auto* const code = state.code.data();
    auto pc = code;
    while (true)  // Guaranteed to terminate because padded code ends with STOP.
    {
        if constexpr (TracingEnabled)
        {
            const auto offset = static_cast<uint32_t>(pc - code);
            if (offset < state.code.size())  // Skip STOP from code padding.
                tracer->notify_instruction_start(offset, state);
        }

        const auto op = *pc;
        const auto status = check_requirements(instruction_table, state, op);
        if (status != EVMC_SUCCESS)
        {
            state.status = status;
            goto exit;
        }

        switch (op)
        {
        case OP_STOP:
            goto exit;

            CASE(ADD)
            CASE(MUL)
            CASE(SUB)
            CASE(DIV)
            CASE(SDIV)
            CASE(MOD)
            CASE(SMOD)
            CASE(ADDMOD)
            CASE(MULMOD)
            CASE(EXP)
            CASE(SIGNEXTEND)

            CASE(LT)
            CASE(GT)
            CASE(SLT)
            CASE(SGT)
            CASE(EQ)
            CASE(ISZERO)
            CASE(AND)
            CASE(OR)
            CASE(XOR)
            CASE(NOT)
            CASE(BYTE)
            CASE(SHL)
            CASE(SHR)
            CASE(SAR)

            CASE(KECCAK256)

            CASE(ADDRESS)
            CASE(BALANCE)
            CASE(ORIGIN)
            CASE(CALLER)
            CASE(CALLVALUE)
            CASE(CALLDATALOAD)
            CASE(CALLDATASIZE)
            CASE(CALLDATACOPY)
            CASE(CODESIZE)
            CASE(CODECOPY)
            CASE(GASPRICE)
            CASE(EXTCODESIZE)
            CASE(EXTCODECOPY)
            CASE(RETURNDATASIZE)
            CASE(RETURNDATACOPY)
            CASE(EXTCODEHASH)
            CASE(BLOCKHASH)
            CASE(COINBASE)
            CASE(TIMESTAMP)
            CASE(NUMBER)
            CASE(DIFFICULTY)
            CASE(GASLIMIT)
            CASE(CHAINID)
            CASE(SELFBALANCE)
            CASE(BASEFEE)

            CASE(POP)
            CASE(MLOAD)
            CASE(MSTORE)
            CASE(MSTORE8)

        case OP_JUMP:
            CHECK_STACK_OVERFLOW(JUMP)
            pc = op_jump(state, analysis.jumpdest_map);
            continue;
        case OP_JUMPI:
            CHECK_STACK_OVERFLOW(JUMPI)
            if (state.stack[1] != 0)
            {
                pc = op_jump(state, analysis.jumpdest_map);
            }
            else
            {
                state.stack.pop();
                ++pc;
            }
            state.stack.pop();
            continue;

        case OP_PC:
            CHECK_STACK_OVERFLOW(PC)
            state.stack.push(pc - code);
            break;
            CASE(MSIZE)
            CASE(SLOAD)
            CASE(SSTORE)
        case OP_GAS:
            CHECK_STACK_OVERFLOW(PC)
            state.stack.push(state.gas_left);
            break;
        case OP_JUMPDEST:
            break;

            CASE_PUSH(1)
            CASE_PUSH(2)
            CASE_PUSH(3)
            CASE_PUSH(4)
            CASE_PUSH(5)
            CASE_PUSH(6)
            CASE_PUSH(7)
            CASE_PUSH(8)
            CASE_PUSH(9)
            CASE_PUSH(10)
            CASE_PUSH(11)
            CASE_PUSH(12)
            CASE_PUSH(13)
            CASE_PUSH(14)
            CASE_PUSH(15)
            CASE_PUSH(16)
            CASE_PUSH(17)
            CASE_PUSH(18)
            CASE_PUSH(19)
            CASE_PUSH(20)
            CASE_PUSH(21)
            CASE_PUSH(22)
            CASE_PUSH(23)
            CASE_PUSH(24)
            CASE_PUSH(25)
            CASE_PUSH(26)
            CASE_PUSH(27)
            CASE_PUSH(28)
            CASE_PUSH(29)
            CASE_PUSH(30)
            CASE_PUSH(31)
            CASE_PUSH(32)

            CASE(DUP1)
            CASE(DUP2)
            CASE(DUP3)
            CASE(DUP4)
            CASE(DUP5)
            CASE(DUP6)
            CASE(DUP7)
            CASE(DUP8)
            CASE(DUP9)
            CASE(DUP10)
            CASE(DUP11)
            CASE(DUP12)
            CASE(DUP13)
            CASE(DUP14)
            CASE(DUP15)
            CASE(DUP16)

            CASE(SWAP1)
            CASE(SWAP2)
            CASE(SWAP3)
            CASE(SWAP4)
            CASE(SWAP5)
            CASE(SWAP6)
            CASE(SWAP7)
            CASE(SWAP8)
            CASE(SWAP9)
            CASE(SWAP10)
            CASE(SWAP11)
            CASE(SWAP12)
            CASE(SWAP13)
            CASE(SWAP14)
            CASE(SWAP15)
            CASE(SWAP16)

            CASE(LOG0)
            CASE(LOG1)
            CASE(LOG2)
            CASE(LOG3)
            CASE(LOG4)

            CASE(CREATE)
            CASE(CALL)
            CASE(CALLCODE)
        case OP_RETURN:
            op_return<EVMC_SUCCESS>(state);
            goto exit;
            CASE(DELEGATECALL)
            CASE(STATICCALL)
            CASE(CREATE2)
        case OP_REVERT:
            op_return<EVMC_REVERT>(state);
            goto exit;
        case OP_INVALID:
            state.status = EVMC_INVALID_INSTRUCTION;
            goto exit;
        case OP_SELFDESTRUCT:
            state.status = selfdestruct(state);
            goto exit;
        default:
            INTX_UNREACHABLE();
        }

        ++pc;
    }

exit:
    const auto gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? state.gas_left : 0;

    const auto result = evmc::make_result(state.status, gas_left,
        state.output_size != 0 ? &state.memory[state.output_offset] : nullptr, state.output_size);

    if constexpr (TracingEnabled)
        tracer->notify_execution_end(result);

    return result;
}
}  // namespace

evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    if (INTX_UNLIKELY(vm.get_tracer() != nullptr))
        return execute<true>(vm, state, analysis);

    return execute<false>(vm, state, analysis);
}

evmc_result execute(evmc_vm* c_vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    auto vm = static_cast<VM*>(c_vm);
    const auto jumpdest_map = analyze(code, code_size);
    auto state = std::make_unique<ExecutionState>(*msg, rev, *host, ctx, code, code_size);
    return execute(*vm, *state, jumpdest_map);
}
}  // namespace evmone::baseline
