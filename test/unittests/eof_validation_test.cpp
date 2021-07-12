// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

using namespace evmone;

TEST(eof_validation, validate_empty_code)
{
    bytes code;
    EXPECT_EQ(
        validate_eof(EVMC_SHANGHAI, code.data(), code.size()), EOFValidationErrror::invalid_prefix);
}
/*
TEST("reject code starting with FORMAT in intermediate period")
{
    CHECK(validate(from_hex("00"), 0) == error_code::success);
    CHECK(validate(from_hex("FE"), 0) == error_code::success);
    CHECK(validate(from_hex("EF"), 0) == error_code::starts_with_format);
}

TEST("validate EOF prefix")
{
    CHECK(validate(from_hex("EFA61C01"), 1) == error_code::section_headers_not_terminated);

    CHECK(validate(from_hex(""), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EF"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA6"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA61C"), 1) == error_code::eof_version_mismatch);

    CHECK(validate(from_hex("EEA61C01"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA71C01"), 1) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA61D01"), 1) == error_code::eof_version_mismatch);
}

TEST("validate EOF version")
{
    CHECK(validate(from_hex("EFA61C01"), 1) == error_code::section_headers_not_terminated);
    CHECK(validate(from_hex("EFA61C02"), 2) == error_code::eof_version_unknown);
    CHECK(validate(from_hex("EFA61CFF"), 0xff) == error_code::eof_version_unknown);

    CHECK(validate(from_hex("EFA61C01"), 2) == error_code::eof_version_mismatch);
    CHECK(validate(from_hex("EFA61C02"), 1) == error_code::eof_version_mismatch);
}

TEST("minimal valid EOF1 code")
{
    CHECK(validate(from_hex("EFA61C01 010001 00 FE"), 1) == error_code::success);
}

TEST("minimal valid EOF1 code with data")
{
    CHECK(validate(from_hex("EFA61C01 010001 020001 00 FE DA"), 1) == error_code::success);
}

TEST("EOF1 code section missing")
{
    CHECK(validate(from_hex("EFA61C01 00"), 1) == error_code::code_section_missing);
    CHECK(validate(from_hex("EFA61C01 020001 DA"), 1) == error_code::code_section_missing);
}

TEST("create legacy contract - success")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = bytes{0};

    CHECK(std::get<bytes>(create_contract_v1(mock, initcode, 0)) == bytes{0});
    CHECK(std::get<bytes>(create_contract_v2(mock, initcode, 0)) == bytes{0});
}

TEST("legacy create transaction - success")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = bytes{0};

    CHECK(std::get<bytes>(execute_create_tx_v1(mock, initcode)) == bytes{0});
    CHECK(std::get<bytes>(execute_create_tx_v2(mock, initcode)) == bytes{0});
}

TEST("legacy create transaction - initcode failure")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = error_code::initcode_failure;

    CHECK(
        std::get<error_code>(execute_create_tx_v1(mock, initcode)) == error_code::initcode_failure);
    CHECK(
        std::get<error_code>(execute_create_tx_v2(mock, initcode)) == error_code::initcode_failure);
}

TEST("legacy create transaction - code starts with FORMAT")
{
    const auto initcode = bytes{0};
    ExecutionMock mock;
    mock.execution_result = bytes{FORMAT, 0};

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, initcode)) ==
          error_code::starts_with_format);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, initcode)) ==
          error_code::starts_with_format);
}

TEST("legacy create transaction - initcode starts with FORMAT")
{
    const auto initcode = bytes{FORMAT};
    ExecutionMock mock;
    mock.execution_result = error_code::initcode_failure;  // FORMAT opcode aborts execution.

    // Here we have different error codes depending on initcode being validated or not.
    // But the end results is the same: create transaction fails.
    CHECK(std::get<error_code>(execute_create_tx_v1(mock, initcode)) ==
          error_code::starts_with_format);
    CHECK(
        std::get<error_code>(execute_create_tx_v2(mock, initcode)) == error_code::initcode_failure);
}

TEST("legacy create transaction - EOF version mismatch")
{
    const auto initcode = bytes{};
    ExecutionMock mock;
    mock.execution_result = from_hex("EFA61C01 010001 00 FE");  // EOF1 code.

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, initcode)) ==
          error_code::eof_version_mismatch);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, initcode)) ==
          error_code::eof_version_mismatch);
}

TEST("EOF1 create transaction - success")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = eof1_code;

    CHECK(std::get<bytes>(execute_create_tx_v1(mock, eof1_code)) == eof1_code);
    CHECK(std::get<bytes>(execute_create_tx_v2(mock, eof1_code)) == eof1_code);
}

TEST("EOF1 create transaction - invalid initcode")
{
    const auto eof2_code = from_hex("EFA61C02");
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = eof1_code;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof2_code)) ==
          error_code::eof_version_unknown);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof2_code)) ==
          error_code::eof_version_unknown);
}

TEST("EOF1 create transaction - initcode failure")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = error_code::initcode_failure;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::initcode_failure);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::initcode_failure);
}

TEST("EOF1 create transaction - EOF version mismatch")
{
    const auto eof2_code = from_hex("EFA61C02");
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = eof2_code;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
}

TEST("EOF1 create transaction - legacy code")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    ExecutionMock mock;
    mock.execution_result = bytes{};  // Legacy code

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::eof_version_mismatch);
}

TEST("EOF1 create transaction - invalid code")
{
    const auto eof1_code = from_hex("EFA61C01 010001 00 FE");
    const auto eof1_code_invalid = from_hex("EFA61C01");
    ExecutionMock mock;
    mock.execution_result = eof1_code_invalid;

    CHECK(std::get<error_code>(execute_create_tx_v1(mock, eof1_code)) ==
          error_code::section_headers_not_terminated);
    CHECK(std::get<error_code>(execute_create_tx_v2(mock, eof1_code)) ==
          error_code::section_headers_not_terminated);
}
*/
