#include "txEnv.h"
#include <haskell/simplicity_ffi.h>

#include <string.h>

/* Construct a txEnv structure from its components.
 * This function will precompute any cached values.
 *
 * Precondition: NULL != tx
 *               NULL != taproot
 *               NULL != genesisHash
 *               ix < tx->numInputs
 */
txEnv simplicity_elements_build_txEnv(const elementsTransaction* tx, const elementsTapEnv* taproot,
                                      const sha256_midstate* genesisHash, uint_fast32_t ix,
                                      bool bmmParentMtpPresent, uint_fast64_t bmmParentMtp,
                                      bool priorActiveBmmParentCheckpointPresent,
                                      const unsigned char priorActiveBmmParentCheckpoint[80]) {
  txEnv result = { .tx = tx
                 , .taproot = taproot
                 , .genesisHash = *genesisHash
                 , .ix = ix
                 , .bmmParentMtp = bmmParentMtp
                 , .bmmParentMtpPresent = bmmParentMtpPresent
                 , .priorActiveBmmParentCheckpointPresent =
                     priorActiveBmmParentCheckpointPresent
                 , .priorActiveBmmParentCheckpointValid =
                     elements_haskell_optional_checkpoint(
                         priorActiveBmmParentCheckpointPresent,
                         priorActiveBmmParentCheckpoint)
                 };
  if (priorActiveBmmParentCheckpoint) {
    memcpy(result.priorActiveBmmParentCheckpoint,
           priorActiveBmmParentCheckpoint, 80);
  }
  sha256_context ctx = sha256_init(result.sigAllHash.s);
  sha256_hash(&ctx, genesisHash);
  sha256_hash(&ctx, genesisHash);
  sha256_hash(&ctx, &tx->txHash);
  sha256_hash(&ctx, &taproot->tapEnvHash);
  sha256_u32be(&ctx, ix);
  sha256_finalize(&ctx);

  return result;
}
