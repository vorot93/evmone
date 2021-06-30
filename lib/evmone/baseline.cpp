// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
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

template <evmc_opcode Op>
inline evmc_status_code check_requirements(ExecutionState& state) noexcept
{
    static constexpr auto tr = instr::traits[Op];

    if constexpr (const auto since = instr::is_defined_since(Op); since != EVMC_FRONTIER)
    {
        if (INTX_UNLIKELY(state.rev < since))
            return EVMC_UNDEFINED_INSTRUCTION;
    }

    if constexpr (tr.stack_height_required > 0)
    {
        if (INTX_UNLIKELY(state.stack.size() < tr.stack_height_required))
            return EVMC_STACK_UNDERFLOW;
    }

    if constexpr (tr.stack_height_change > 0)
    {
        if (INTX_UNLIKELY(state.stack.size() == Stack::limit))
            return EVMC_STACK_OVERFLOW;
    }

    if constexpr (instr::has_const_gas_cost(Op))
    {
        if (INTX_UNLIKELY((state.gas_left -= instr::gas_costs[EVMC_FRONTIER][Op]) < 0))
            return EVMC_OUT_OF_GAS;
    }
    else
    {
        if (INTX_UNLIKELY((state.gas_left -= instr::gas_costs[state.rev][Op]) < 0))
            return EVMC_OUT_OF_GAS;
    }

    return EVMC_SUCCESS;
}

#define TARGET(OPCODE)                  \
    OP_##OPCODE : asm("# OP_" #OPCODE); \
    TARGET_##OPCODE
#define CONTINUE goto* cgoto_table[*pc];
#define NEXT \
    ++pc;    \
    CONTINUE

#define IMPL(OPCODE)                                                                        \
    if (const auto status = check_requirements<OP_##OPCODE>(state); status != EVMC_SUCCESS) \
    {                                                                                       \
        state.status = status;                                                              \
        goto exit;                                                                          \
    }                                                                                       \
    (void)0

#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wpedantic"

// bool x = [] {
//     for (size_t i = 0; i <= 0xff; ++i)
//     {
//         if (instr::traits[i].name)
//             std::cerr << instr::traits[i].name << "\n";
//         else
//             std::cerr << "UNDEFINED\n";
//     }
//     return true;
// }();

template <bool TracingEnabled>
evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
    static constexpr void* cgoto_table[256] = {
        &&TARGET_STOP,
        &&TARGET_ADD,
        &&TARGET_MUL,
        &&TARGET_SUB,
        &&TARGET_DIV,
        &&TARGET_SDIV,
        &&TARGET_MOD,
        &&TARGET_SMOD,
        &&TARGET_ADDMOD,
        &&TARGET_MULMOD,
        &&TARGET_EXP,
        &&TARGET_SIGNEXTEND,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_LT,
        &&TARGET_GT,
        &&TARGET_SLT,
        &&TARGET_SGT,
        &&TARGET_EQ,
        &&TARGET_ISZERO,
        &&TARGET_AND,
        &&TARGET_OR,
        &&TARGET_XOR,
        &&TARGET_NOT,
        &&TARGET_BYTE,
        &&TARGET_SHL,
        &&TARGET_SHR,
        &&TARGET_SAR,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_KECCAK256,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_ADDRESS,
        &&TARGET_BALANCE,
        &&TARGET_ORIGIN,
        &&TARGET_CALLER,
        &&TARGET_CALLVALUE,
        &&TARGET_CALLDATALOAD,
        &&TARGET_CALLDATASIZE,
        &&TARGET_CALLDATACOPY,
        &&TARGET_CODESIZE,
        &&TARGET_CODECOPY,
        &&TARGET_GASPRICE,
        &&TARGET_EXTCODESIZE,
        &&TARGET_EXTCODECOPY,
        &&TARGET_RETURNDATASIZE,
        &&TARGET_RETURNDATACOPY,
        &&TARGET_EXTCODEHASH,
        &&TARGET_BLOCKHASH,
        &&TARGET_COINBASE,
        &&TARGET_TIMESTAMP,
        &&TARGET_NUMBER,
        &&TARGET_DIFFICULTY,
        &&TARGET_GASLIMIT,
        &&TARGET_CHAINID,
        &&TARGET_SELFBALANCE,
        &&TARGET_BASEFEE,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_POP,
        &&TARGET_MLOAD,
        &&TARGET_MSTORE,
        &&TARGET_MSTORE8,
        &&TARGET_SLOAD,
        &&TARGET_SSTORE,
        &&TARGET_JUMP,
        &&TARGET_JUMPI,
        &&TARGET_PC,
        &&TARGET_MSIZE,
        &&TARGET_GAS,
        &&TARGET_JUMPDEST,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_PUSH1,
        &&TARGET_PUSH2,
        &&TARGET_PUSH3,
        &&TARGET_PUSH4,
        &&TARGET_PUSH5,
        &&TARGET_PUSH6,
        &&TARGET_PUSH7,
        &&TARGET_PUSH8,
        &&TARGET_PUSH9,
        &&TARGET_PUSH10,
        &&TARGET_PUSH11,
        &&TARGET_PUSH12,
        &&TARGET_PUSH13,
        &&TARGET_PUSH14,
        &&TARGET_PUSH15,
        &&TARGET_PUSH16,
        &&TARGET_PUSH17,
        &&TARGET_PUSH18,
        &&TARGET_PUSH19,
        &&TARGET_PUSH20,
        &&TARGET_PUSH21,
        &&TARGET_PUSH22,
        &&TARGET_PUSH23,
        &&TARGET_PUSH24,
        &&TARGET_PUSH25,
        &&TARGET_PUSH26,
        &&TARGET_PUSH27,
        &&TARGET_PUSH28,
        &&TARGET_PUSH29,
        &&TARGET_PUSH30,
        &&TARGET_PUSH31,
        &&TARGET_PUSH32,
        &&TARGET_DUP1,
        &&TARGET_DUP2,
        &&TARGET_DUP3,
        &&TARGET_DUP4,
        &&TARGET_DUP5,
        &&TARGET_DUP6,
        &&TARGET_DUP7,
        &&TARGET_DUP8,
        &&TARGET_DUP9,
        &&TARGET_DUP10,
        &&TARGET_DUP11,
        &&TARGET_DUP12,
        &&TARGET_DUP13,
        &&TARGET_DUP14,
        &&TARGET_DUP15,
        &&TARGET_DUP16,
        &&TARGET_SWAP1,
        &&TARGET_SWAP2,
        &&TARGET_SWAP3,
        &&TARGET_SWAP4,
        &&TARGET_SWAP5,
        &&TARGET_SWAP6,
        &&TARGET_SWAP7,
        &&TARGET_SWAP8,
        &&TARGET_SWAP9,
        &&TARGET_SWAP10,
        &&TARGET_SWAP11,
        &&TARGET_SWAP12,
        &&TARGET_SWAP13,
        &&TARGET_SWAP14,
        &&TARGET_SWAP15,
        &&TARGET_SWAP16,
        &&TARGET_LOG0,
        &&TARGET_LOG1,
        &&TARGET_LOG2,
        &&TARGET_LOG3,
        &&TARGET_LOG4,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_CREATE,
        &&TARGET_CALL,
        &&TARGET_CALLCODE,
        &&TARGET_RETURN,
        &&TARGET_DELEGATECALL,
        &&TARGET_CREATE2,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_STATICCALL,
        &&TARGET_UNDEFINED,
        &&TARGET_UNDEFINED,
        &&TARGET_REVERT,
        &&TARGET_INVALID,
        &&TARGET_SELFDESTRUCT,
    };

    // Use padded code.
    state.code = {analysis.padded_code.get(), state.code.size()};

    auto* tracer = vm.get_tracer();
    if constexpr (TracingEnabled)
        tracer->notify_execution_start(state.rev, *state.msg, state.code);

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
        switch (op)
        {
        case TARGET(STOP):
            IMPL(STOP);
            goto exit;
        case TARGET(ADD):
            IMPL(ADD);
            add(state);
            NEXT;
        case TARGET(MUL):
            IMPL(MUL);
            mul(state);
            NEXT;
        case TARGET(SUB):
            IMPL(SUB);
            sub(state);
            NEXT;
        case TARGET(DIV):
            IMPL(DIV);
            div(state);
            NEXT;
        case TARGET(SDIV):
            IMPL(SDIV);
            sdiv(state);
            NEXT;
        case TARGET(MOD):
            IMPL(MOD);
            mod(state);
            NEXT;
        case TARGET(SMOD):
            IMPL(SMOD);
            smod(state);
            NEXT;
        case TARGET(ADDMOD):
            IMPL(ADDMOD);
            addmod(state);
            NEXT;
        case TARGET(MULMOD):
            IMPL(MULMOD);
            mulmod(state);
            NEXT;
        case TARGET(EXP):
            IMPL(EXP);
            {
                const auto status_code = exp(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(SIGNEXTEND):
            IMPL(SIGNEXTEND);
            signextend(state);
            NEXT;

        case TARGET(LT):
            IMPL(LT);
            lt(state);
            NEXT;
        case TARGET(GT):
            IMPL(GT);
            gt(state);
            NEXT;
        case TARGET(SLT):
            IMPL(SLT);
            slt(state);
            NEXT;
        case TARGET(SGT):
            IMPL(SGT);
            sgt(state);
            NEXT;
        case TARGET(EQ):
            IMPL(EQ);
            eq(state);
            NEXT;
        case TARGET(ISZERO):
            IMPL(ISZERO);
            iszero(state);
            NEXT;
        case TARGET(AND):
            IMPL(AND);
            and_(state);
            NEXT;
        case TARGET(OR):
            IMPL(OR);
            or_(state);
            NEXT;
        case TARGET(XOR):
            IMPL(XOR);
            xor_(state);
            NEXT;
        case TARGET(NOT):
            IMPL(NOT);
            not_(state);
            NEXT;
        case TARGET(BYTE):
            IMPL(BYTE);
            byte(state);
            NEXT;
        case TARGET(SHL):
            IMPL(SHL);
            shl(state);
            NEXT;
        case TARGET(SHR):
            IMPL(SHR);
            shr(state);
            NEXT;
        case TARGET(SAR):
            IMPL(SAR);
            sar(state);
            NEXT;

        case TARGET(KECCAK256):
            IMPL(KECCAK256);
            {
                const auto status_code = keccak256(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }

        case TARGET(ADDRESS):
            IMPL(ADDRESS);
            address(state);
            NEXT;
        case TARGET(BALANCE):
            IMPL(BALANCE);
            {
                const auto status_code = balance(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(ORIGIN):
            IMPL(ORIGIN);
            origin(state);
            NEXT;
        case TARGET(CALLER):
            IMPL(CALLER);
            caller(state);
            NEXT;
        case TARGET(CALLVALUE):
            IMPL(CALLVALUE);
            callvalue(state);
            NEXT;
        case TARGET(CALLDATALOAD):
            IMPL(CALLDATALOAD);
            calldataload(state);
            NEXT;
        case TARGET(CALLDATASIZE):
            IMPL(CALLDATASIZE);
            calldatasize(state);
            NEXT;
        case TARGET(CALLDATACOPY):
            IMPL(CALLDATACOPY);
            {
                const auto status_code = calldatacopy(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(CODESIZE):
            IMPL(CODESIZE);
            codesize(state);
            NEXT;
        case TARGET(CODECOPY):
            IMPL(CODECOPY);
            {
                const auto status_code = codecopy(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(GASPRICE):
            IMPL(GASPRICE);
            gasprice(state);
            NEXT;
        case TARGET(EXTCODESIZE):
            IMPL(EXTCODESIZE);
            {
                const auto status_code = extcodesize(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(EXTCODECOPY):
            IMPL(EXTCODECOPY);
            {
                const auto status_code = extcodecopy(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(RETURNDATASIZE):
            IMPL(RETURNDATASIZE);
            returndatasize(state);
            NEXT;
        case TARGET(RETURNDATACOPY):
            IMPL(RETURNDATACOPY);
            {
                const auto status_code = returndatacopy(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(EXTCODEHASH):
            IMPL(EXTCODEHASH);
            {
                const auto status_code = extcodehash(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(BLOCKHASH):
            IMPL(BLOCKHASH);
            blockhash(state);
            NEXT;
        case TARGET(COINBASE):
            IMPL(COINBASE);
            coinbase(state);
            NEXT;
        case TARGET(TIMESTAMP):
            IMPL(TIMESTAMP);
            timestamp(state);
            NEXT;
        case TARGET(NUMBER):
            IMPL(NUMBER);
            number(state);
            NEXT;
        case TARGET(DIFFICULTY):
            IMPL(DIFFICULTY);
            difficulty(state);
            NEXT;
        case TARGET(GASLIMIT):
            IMPL(GASLIMIT);
            gaslimit(state);
            NEXT;
        case TARGET(CHAINID):
            IMPL(CHAINID);
            chainid(state);
            NEXT;
        case TARGET(SELFBALANCE):
            IMPL(SELFBALANCE);
            selfbalance(state);
            NEXT;
        case TARGET(BASEFEE):
            IMPL(BASEFEE);
            basefee(state);
            NEXT;

        case TARGET(POP):
            IMPL(POP);
            pop(state);
            NEXT;
        case TARGET(MLOAD):
            IMPL(MLOAD);
            {
                const auto status_code = mload(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(MSTORE):
            IMPL(MSTORE);
            {
                const auto status_code = mstore(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(MSTORE8):
            IMPL(MSTORE8);
            {
                const auto status_code = mstore8(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }

        case TARGET(JUMP):
            IMPL(JUMP);
            pc = op_jump(state, analysis.jumpdest_map);
            CONTINUE;
        case TARGET(JUMPI):
            IMPL(JUMPI);
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
            CONTINUE;

        case TARGET(PC):
            IMPL(PC);
            state.stack.push(pc - code);
            NEXT;
        case TARGET(MSIZE):
            IMPL(MSIZE);
            msize(state);
            NEXT;
        case TARGET(SLOAD):
            IMPL(SLOAD);
            {
                const auto status_code = sload(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(SSTORE):
            IMPL(SSTORE);
            {
                const auto status_code = sstore(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(GAS):
            IMPL(GAS);
            state.stack.push(state.gas_left);
            NEXT;
        case TARGET(JUMPDEST):
            IMPL(JUMPDEST);
            NEXT;

        case TARGET(PUSH1):
            IMPL(PUSH1);
            pc = load_push<1>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH2):
            IMPL(PUSH2);
            pc = load_push<2>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH3):
            IMPL(PUSH3);
            pc = load_push<3>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH4):
            IMPL(PUSH4);
            pc = load_push<4>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH5):
            IMPL(PUSH5);
            pc = load_push<5>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH6):
            IMPL(PUSH6);
            pc = load_push<6>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH7):
            IMPL(PUSH7);
            pc = load_push<7>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH8):
            IMPL(PUSH8);
            pc = load_push<8>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH9):
            IMPL(PUSH9);
            pc = load_push<9>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH10):
            IMPL(PUSH10);
            pc = load_push<10>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH11):
            IMPL(PUSH11);
            pc = load_push<11>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH12):
            IMPL(PUSH12);
            pc = load_push<12>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH13):
            IMPL(PUSH13);
            pc = load_push<13>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH14):
            IMPL(PUSH14);
            pc = load_push<14>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH15):
            IMPL(PUSH15);
            pc = load_push<15>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH16):
            IMPL(PUSH16);
            pc = load_push<16>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH17):
            IMPL(PUSH17);
            pc = load_push<17>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH18):
            IMPL(PUSH18);
            pc = load_push<18>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH19):
            IMPL(PUSH19);
            pc = load_push<19>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH20):
            IMPL(PUSH20);
            pc = load_push<20>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH21):
            IMPL(PUSH21);
            pc = load_push<21>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH22):
            IMPL(PUSH22);
            pc = load_push<22>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH23):
            IMPL(PUSH23);
            pc = load_push<23>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH24):
            IMPL(PUSH24);
            pc = load_push<24>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH25):
            IMPL(PUSH25);
            pc = load_push<25>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH26):
            IMPL(PUSH26);
            pc = load_push<26>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH27):
            IMPL(PUSH27);
            pc = load_push<27>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH28):
            IMPL(PUSH28);
            pc = load_push<28>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH29):
            IMPL(PUSH29);
            pc = load_push<29>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH30):
            IMPL(PUSH30);
            pc = load_push<30>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH31):
            IMPL(PUSH31);
            pc = load_push<31>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH32):
            IMPL(PUSH32);
            pc = load_push<32>(state, pc + 1);
            CONTINUE;

        case TARGET(DUP1):
            IMPL(DUP1);
            dup<1>(state);
            NEXT;
        case TARGET(DUP2):
            IMPL(DUP2);
            dup<2>(state);
            NEXT;
        case TARGET(DUP3):
            IMPL(DUP3);
            dup<3>(state);
            NEXT;
        case TARGET(DUP4):
            IMPL(DUP4);
            dup<4>(state);
            NEXT;
        case TARGET(DUP5):
            IMPL(DUP5);
            dup<5>(state);
            NEXT;
        case TARGET(DUP6):
            IMPL(DUP6);
            dup<6>(state);
            NEXT;
        case TARGET(DUP7):
            IMPL(DUP7);
            dup<7>(state);
            NEXT;
        case TARGET(DUP8):
            IMPL(DUP8);
            dup<8>(state);
            NEXT;
        case TARGET(DUP9):
            IMPL(DUP9);
            dup<9>(state);
            NEXT;
        case TARGET(DUP10):
            IMPL(DUP10);
            dup<10>(state);
            NEXT;
        case TARGET(DUP11):
            IMPL(DUP11);
            dup<11>(state);
            NEXT;
        case TARGET(DUP12):
            IMPL(DUP12);
            dup<12>(state);
            NEXT;
        case TARGET(DUP13):
            IMPL(DUP13);
            dup<13>(state);
            NEXT;
        case TARGET(DUP14):
            IMPL(DUP14);
            dup<14>(state);
            NEXT;
        case TARGET(DUP15):
            IMPL(DUP15);
            dup<15>(state);
            NEXT;
        case TARGET(DUP16):
            IMPL(DUP16);
            dup<16>(state);
            NEXT;

        case TARGET(SWAP1):
            IMPL(SWAP1);
            swap<1>(state);
            NEXT;
        case TARGET(SWAP2):
            IMPL(SWAP2);
            swap<2>(state);
            NEXT;
        case TARGET(SWAP3):
            IMPL(SWAP3);
            swap<3>(state);
            NEXT;
        case TARGET(SWAP4):
            IMPL(SWAP4);
            swap<4>(state);
            NEXT;
        case TARGET(SWAP5):
            IMPL(SWAP5);
            swap<5>(state);
            NEXT;
        case TARGET(SWAP6):
            IMPL(SWAP6);
            swap<6>(state);
            NEXT;
        case TARGET(SWAP7):
            IMPL(SWAP7);
            swap<7>(state);
            NEXT;
        case TARGET(SWAP8):
            IMPL(SWAP8);
            swap<8>(state);
            NEXT;
        case TARGET(SWAP9):
            IMPL(SWAP9);
            swap<9>(state);
            NEXT;
        case TARGET(SWAP10):
            IMPL(SWAP10);
            swap<10>(state);
            NEXT;
        case TARGET(SWAP11):
            IMPL(SWAP11);
            swap<11>(state);
            NEXT;
        case TARGET(SWAP12):
            IMPL(SWAP12);
            swap<12>(state);
            NEXT;
        case TARGET(SWAP13):
            IMPL(SWAP13);
            swap<13>(state);
            NEXT;
        case TARGET(SWAP14):
            IMPL(SWAP14);
            swap<14>(state);
            NEXT;
        case TARGET(SWAP15):
            IMPL(SWAP15);
            swap<15>(state);
            NEXT;
        case TARGET(SWAP16):
            IMPL(SWAP16);
            swap<16>(state);
            NEXT;

        case TARGET(LOG0):
            IMPL(LOG0);
            {
                const auto status_code = log<0>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(LOG1):
            IMPL(LOG1);
            {
                const auto status_code = log<1>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(LOG2):
            IMPL(LOG2);
            {
                const auto status_code = log<2>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(LOG3):
            IMPL(LOG3);
            {
                const auto status_code = log<3>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(LOG4):
            IMPL(LOG4);
            {
                const auto status_code = log<4>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }

        case TARGET(CREATE):
            IMPL(CREATE);
            {
                const auto status_code = create<EVMC_CREATE>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(CALL):
            IMPL(CALL);
            {
                const auto status_code = call<EVMC_CALL>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(CALLCODE):
            IMPL(CALLCODE);
            {
                const auto status_code = call<EVMC_CALLCODE>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(RETURN):
            IMPL(RETURN);
            return_<EVMC_SUCCESS>(state);
            goto exit;
        case TARGET(DELEGATECALL):
            IMPL(DELEGATECALL);
            {
                const auto status_code = call<EVMC_DELEGATECALL>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(STATICCALL):
            IMPL(STATICCALL);
            {
                const auto status_code = call<EVMC_CALL, true>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(CREATE2):
            IMPL(CREATE2);
            {
                const auto status_code = create<EVMC_CREATE2>(state);
                if (status_code != EVMC_SUCCESS)
                {
                    state.status = status_code;
                    goto exit;
                }
                NEXT;
            }
        case TARGET(REVERT):
            IMPL(REVERT);
            return_<EVMC_REVERT>(state);
            goto exit;
        case TARGET(INVALID):
            IMPL(INVALID);
            state.status = EVMC_INVALID_INSTRUCTION;
            goto exit;
        case TARGET(SELFDESTRUCT):
            IMPL(SELFDESTRUCT);
            state.status = selfdestruct(state);
            goto exit;
        default:
        TARGET_UNDEFINED:
            state.status = EVMC_UNDEFINED_INSTRUCTION;
            goto exit;
        }
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
