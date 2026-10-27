// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef ELEMENTS_HASKELL_SIMPLICITY_FFI_H
#define ELEMENTS_HASKELL_SIMPLICITY_FFI_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* All functions and buffers must remain valid until this synchronous call returns. */
bool elements_haskell_jet_height(bool present, uint64_t height);
bool elements_haskell_optional_environment(uint32_t kind, uint32_t present, uint32_t fields);
bool elements_haskell_optional_checkpoint(bool present, const unsigned char* checkpoint);
#ifdef __cplusplus
}
#endif
#endif
