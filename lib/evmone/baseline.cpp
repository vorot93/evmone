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

inline evmc_status_code check_requirements(
    const InstructionTable& instruction_table, ExecutionState& state, uint8_t op) noexcept
{
    const auto metrics = instruction_table[op];

    if (INTX_UNLIKELY(metrics.gas_cost == instr::undefined))
        return EVMC_UNDEFINED_INSTRUCTION;

    if (INTX_UNLIKELY((state.gas_left -= metrics.gas_cost) < 0))
        return EVMC_OUT_OF_GAS;

    const auto stack_size = state.stack.size();
    if (INTX_UNLIKELY(stack_size == Stack::limit))
    {
        if (metrics.can_overflow_stack)
            return EVMC_STACK_OVERFLOW;
    }
    else if (INTX_UNLIKELY(stack_size < metrics.stack_height_required))
        return EVMC_STACK_UNDERFLOW;

    return EVMC_SUCCESS;
}

#define TARGET(OPCODE)                  \
    OP_##OPCODE : asm("# OP_" #OPCODE); \
    TARGET_##OPCODE
#define CONTINUE break
#define NEXT \
    ++pc;    \
    CONTINUE

#pragma GCC diagnostic ignored "-Wunused-label"

template <bool TracingEnabled>
evmc_result execute(const VM& vm, ExecutionState& state, const CodeAnalysis& analysis) noexcept
{
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
        case TARGET(STOP):
            goto exit;
        case TARGET(ADD):
            add(state);
            NEXT;
        case TARGET(MUL):
            mul(state);
            NEXT;
        case TARGET(SUB):
            sub(state);
            NEXT;
        case TARGET(DIV):
            div(state);
            NEXT;
        case TARGET(SDIV):
            sdiv(state);
            NEXT;
        case TARGET(MOD):
            mod(state);
            NEXT;
        case TARGET(SMOD):
            smod(state);
            NEXT;
        case TARGET(ADDMOD):
            addmod(state);
            NEXT;
        case TARGET(MULMOD):
            mulmod(state);
            NEXT;
        case TARGET(EXP):
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
            signextend(state);
            NEXT;

        case TARGET(LT):
            lt(state);
            NEXT;
        case TARGET(GT):
            gt(state);
            NEXT;
        case TARGET(SLT):
            slt(state);
            NEXT;
        case TARGET(SGT):
            sgt(state);
            NEXT;
        case TARGET(EQ):
            eq(state);
            NEXT;
        case TARGET(ISZERO):
            iszero(state);
            NEXT;
        case TARGET(AND):
            and_(state);
            NEXT;
        case TARGET(OR):
            or_(state);
            NEXT;
        case TARGET(XOR):
            xor_(state);
            NEXT;
        case TARGET(NOT):
            not_(state);
            NEXT;
        case TARGET(BYTE):
            byte(state);
            NEXT;
        case TARGET(SHL):
            shl(state);
            NEXT;
        case TARGET(SHR):
            shr(state);
            NEXT;
        case TARGET(SAR):
            sar(state);
            NEXT;

        case TARGET(KECCAK256):
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
            address(state);
            NEXT;
        case TARGET(BALANCE):
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
            origin(state);
            NEXT;
        case TARGET(CALLER):
            caller(state);
            NEXT;
        case TARGET(CALLVALUE):
            callvalue(state);
            NEXT;
        case TARGET(CALLDATALOAD):
            calldataload(state);
            NEXT;
        case TARGET(CALLDATASIZE):
            calldatasize(state);
            NEXT;
        case TARGET(CALLDATACOPY):
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
            codesize(state);
            NEXT;
        case TARGET(CODECOPY):
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
            gasprice(state);
            NEXT;
        case TARGET(EXTCODESIZE):
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
            returndatasize(state);
            NEXT;
        case TARGET(RETURNDATACOPY):
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
            blockhash(state);
            NEXT;
        case TARGET(COINBASE):
            coinbase(state);
            NEXT;
        case TARGET(TIMESTAMP):
            timestamp(state);
            NEXT;
        case TARGET(NUMBER):
            number(state);
            NEXT;
        case TARGET(DIFFICULTY):
            difficulty(state);
            NEXT;
        case TARGET(GASLIMIT):
            gaslimit(state);
            NEXT;
        case TARGET(CHAINID):
            chainid(state);
            NEXT;
        case TARGET(SELFBALANCE):
            selfbalance(state);
            NEXT;
        case TARGET(BASEFEE):
            basefee(state);
            NEXT;

        case TARGET(POP):
            pop(state);
            NEXT;
        case TARGET(MLOAD):
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
            pc = op_jump(state, analysis.jumpdest_map);
            CONTINUE;
        case TARGET(JUMPI):
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
            state.stack.push(pc - code);
            NEXT;
        case TARGET(MSIZE):
            msize(state);
            NEXT;
        case TARGET(SLOAD):
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
            state.stack.push(state.gas_left);
            NEXT;
        case TARGET(JUMPDEST):
            NEXT;

        case TARGET(PUSH1):
            pc = load_push<1>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH2):
            pc = load_push<2>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH3):
            pc = load_push<3>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH4):
            pc = load_push<4>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH5):
            pc = load_push<5>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH6):
            pc = load_push<6>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH7):
            pc = load_push<7>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH8):
            pc = load_push<8>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH9):
            pc = load_push<9>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH10):
            pc = load_push<10>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH11):
            pc = load_push<11>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH12):
            pc = load_push<12>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH13):
            pc = load_push<13>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH14):
            pc = load_push<14>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH15):
            pc = load_push<15>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH16):
            pc = load_push<16>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH17):
            pc = load_push<17>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH18):
            pc = load_push<18>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH19):
            pc = load_push<19>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH20):
            pc = load_push<20>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH21):
            pc = load_push<21>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH22):
            pc = load_push<22>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH23):
            pc = load_push<23>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH24):
            pc = load_push<24>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH25):
            pc = load_push<25>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH26):
            pc = load_push<26>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH27):
            pc = load_push<27>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH28):
            pc = load_push<28>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH29):
            pc = load_push<29>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH30):
            pc = load_push<30>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH31):
            pc = load_push<31>(state, pc + 1);
            CONTINUE;
        case TARGET(PUSH32):
            pc = load_push<32>(state, pc + 1);
            CONTINUE;

        case TARGET(DUP1):
            dup<1>(state);
            NEXT;
        case TARGET(DUP2):
            dup<2>(state);
            NEXT;
        case TARGET(DUP3):
            dup<3>(state);
            NEXT;
        case TARGET(DUP4):
            dup<4>(state);
            NEXT;
        case TARGET(DUP5):
            dup<5>(state);
            NEXT;
        case TARGET(DUP6):
            dup<6>(state);
            NEXT;
        case TARGET(DUP7):
            dup<7>(state);
            NEXT;
        case TARGET(DUP8):
            dup<8>(state);
            NEXT;
        case TARGET(DUP9):
            dup<9>(state);
            NEXT;
        case TARGET(DUP10):
            dup<10>(state);
            NEXT;
        case TARGET(DUP11):
            dup<11>(state);
            NEXT;
        case TARGET(DUP12):
            dup<12>(state);
            NEXT;
        case TARGET(DUP13):
            dup<13>(state);
            NEXT;
        case TARGET(DUP14):
            dup<14>(state);
            NEXT;
        case TARGET(DUP15):
            dup<15>(state);
            NEXT;
        case TARGET(DUP16):
            dup<16>(state);
            NEXT;

        case TARGET(SWAP1):
            swap<1>(state);
            NEXT;
        case TARGET(SWAP2):
            swap<2>(state);
            NEXT;
        case TARGET(SWAP3):
            swap<3>(state);
            NEXT;
        case TARGET(SWAP4):
            swap<4>(state);
            NEXT;
        case TARGET(SWAP5):
            swap<5>(state);
            NEXT;
        case TARGET(SWAP6):
            swap<6>(state);
            NEXT;
        case TARGET(SWAP7):
            swap<7>(state);
            NEXT;
        case TARGET(SWAP8):
            swap<8>(state);
            NEXT;
        case TARGET(SWAP9):
            swap<9>(state);
            NEXT;
        case TARGET(SWAP10):
            swap<10>(state);
            NEXT;
        case TARGET(SWAP11):
            swap<11>(state);
            NEXT;
        case TARGET(SWAP12):
            swap<12>(state);
            NEXT;
        case TARGET(SWAP13):
            swap<13>(state);
            NEXT;
        case TARGET(SWAP14):
            swap<14>(state);
            NEXT;
        case TARGET(SWAP15):
            swap<15>(state);
            NEXT;
        case TARGET(SWAP16):
            swap<16>(state);
            NEXT;

        case TARGET(LOG0):
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
            return_<EVMC_SUCCESS>(state);
            goto exit;
        case TARGET(DELEGATECALL):
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
            return_<EVMC_REVERT>(state);
            goto exit;
        case TARGET(INVALID):
            state.status = EVMC_INVALID_INSTRUCTION;
            goto exit;
        case TARGET(SELFDESTRUCT):
            state.status = selfdestruct(state);
            goto exit;
        default:
            INTX_UNREACHABLE();
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
