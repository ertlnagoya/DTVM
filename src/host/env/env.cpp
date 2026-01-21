// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common/errors.h"
#include "runtime/instance.h"
// Note: must place env.h after instance.h to get correct EXPORT_MODULE_NAME
#include "host/env/env.h"

#include <cstring>

namespace zen::host {

static void *vnmi_init_ctx(VNMIEnv *vmenv, const char *dir_list[],
                           uint32_t dir_count, const char *envs[],
                           uint32_t env_count, char *env_buf,
                           uint32_t env_buf_size, char *argv[], uint32_t argc,
                           char *argv_buf, uint32_t argv_buf_size) {
  return nullptr;
}

static void vnmi_destroy_ctx(VNMIEnv *vmenv, void *ctx) {}

#ifdef ZEN_ENABLE_MOCK_CHAIN_TEST
#include "host/env/mock_chain.inc.cpp"
#else
#define MOCK_CHAIN_HOST_API_LIST
#endif

#ifdef ZEN_ENABLE_BUILTIN_LIBC
#include "host/env/libc.inc.cpp"
#else
#define LIBC_HOST_API_LIST
#endif

/// Select abort implementation according to Macro-Definition
#ifdef ZEN_ENABLE_MOCK_CHAIN_TEST
static void abort(zen::runtime::Instance *Inst) {
  MOCK_CHAIN_DUMMY_IMPLEMENTATION
}
#elif defined(ZEN_ENABLE_ASSEMBLYSCRIPT_TEST)
static void abort(Instance *instance, int32_t a, int32_t b, int32_t c,
                  int32_t d) {
  using namespace common;
  char buf[32];
  snprintf(buf, sizeof(buf), "(%d, %d, %d, %d)", a, b, c, d);
  instance->setExceptionByHostapi(
      getErrorWithExtraMessage(ErrorCode::EnvAbort, buf));
}
#elif defined(ZEN_ENABLE_BUILTIN_LIBC)
static void abort(Instance *instance, int32_t code) {
  using namespace common;
  char buf[16];
  snprintf(buf, sizeof(buf), "(%d)", code);
  instance->setExceptionByHostapi(
      getErrorWithExtraMessage(ErrorCode::EnvAbort, buf));
}
#else
static void abort(Instance *instance) {
  using namespace common;
  instance->setExceptionByHostapi(getError(ErrorCode::EnvAbort));
}
#endif

static void report_abort(Instance *instance,
                         const char *msg = nullptr) {
  using namespace common;
  if (msg) {
    instance->setExceptionByHostapi(getErrorWithExtraMessage(
        ErrorCode::EnvAbort, msg));
  } else {
    instance->setExceptionByHostapi(getError(ErrorCode::EnvAbort));
  }
}

static bool zeroed_result(Instance *instance, int32_t ResultOffset,
                          size_t length) {
  if (!VALIDATE_APP_ADDR(ResultOffset, length)) {
    report_abort(instance, "env: invalid memory range");
    return false;
  }
  std::memset(ADDR_APP_TO_NATIVE(ResultOffset), 0, length);
  return true;
}

static int32_t getCallDataSize(Instance *instance) {
  (void)instance;
  return 4;
}

static void callDataCopy(Instance *instance, int32_t ResultOffset,
                         int32_t DataOffset, int32_t Length) {
  if (Length <= 0) {
    return;
  }
  if (!zeroed_result(instance, ResultOffset, Length)) {
    return;
  }
  (void)DataOffset;
}

static void getCaller(Instance *instance, int32_t ResultOffset) {
  zeroed_result(instance, ResultOffset, 20);
}

static void getCallValue(Instance *instance, int32_t ResultOffset) {
  zeroed_result(instance, ResultOffset, 32);
}

static void revert(Instance *instance, int32_t DataOffset, int32_t Length) {
  (void)DataOffset;
  (void)Length;
  report_abort(instance, "env: revert");
}

static void finish(Instance *instance, int32_t DataOffset, int32_t Length) {
  (void)DataOffset;
  (void)Length;
  instance->setError(common::ErrorCode::InstanceExit);
}

static int32_t getCodeSize(Instance *instance) {
  (void)instance;
  return 0;
}

static void codeCopy(Instance *instance, int32_t ResultOffset,
                     int32_t CodeOffset, int32_t Length) {
  (void)instance;
  (void)CodeOffset;
  (void)Length;
  zeroed_result(instance, ResultOffset, (Length > 0) ? Length : 0);
}

static void storageStore(Instance *instance, int32_t KeyOffset,
                         int32_t ValueOffset) {
  (void)instance;
  (void)KeyOffset;
  (void)ValueOffset;
}

static void storageLoad(Instance *instance, int32_t KeyOffset,
                        int32_t ResultOffset) {
  (void)KeyOffset;
  zeroed_result(instance, ResultOffset, 32);
}

static void keccak256(Instance *instance, int32_t InputOffset,
                      int32_t InputLength, int32_t ResultOffset) {
  (void)instance;
  (void)InputOffset;
  (void)InputLength;
  zeroed_result(instance, ResultOffset, 32);
}

static void emitLogEvent(Instance *instance, int32_t DataOffset,
                         int32_t Length, int32_t NumTopics,
                         int32_t Topic1Offset, int32_t Topic2Offset,
                         int32_t Topic3Offset, int32_t Topic4Offset) {
  (void)instance;
  (void)DataOffset;
  (void)Length;
  (void)NumTopics;
  (void)Topic1Offset;
  (void)Topic2Offset;
  (void)Topic3Offset;
  (void)Topic4Offset;
}

#define FUNCTION_LISTS                                                         \
  MOCK_CHAIN_HOST_API_LIST                                                     \
  LIBC_HOST_API_LIST                                                           \
  NATIVE_FUNC_ENTRY(getCallDataSize)                                           \
  NATIVE_FUNC_ENTRY(callDataCopy)                                              \
  NATIVE_FUNC_ENTRY(getCaller)                                                 \
  NATIVE_FUNC_ENTRY(getCallValue)                                              \
  NATIVE_FUNC_ENTRY(revert)                                                    \
  NATIVE_FUNC_ENTRY(finish)                                                    \
  NATIVE_FUNC_ENTRY(getCodeSize)                                               \
  NATIVE_FUNC_ENTRY(codeCopy)                                                  \
  NATIVE_FUNC_ENTRY(storageStore)                                              \
  NATIVE_FUNC_ENTRY(storageLoad)                                               \
  NATIVE_FUNC_ENTRY(keccak256)                                                 \
  NATIVE_FUNC_ENTRY(emitLogEvent)                                              \
  NATIVE_FUNC_ENTRY(abort)

/*
  the following code are auto generated,
  don't modify it unless you know it exactly.
*/
#include "wni/boilerplate.cpp"

} // namespace zen::host
