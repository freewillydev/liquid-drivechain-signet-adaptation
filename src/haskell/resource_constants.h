// Generated from BmmConstants.resourceHeader; do not edit.
#ifndef ELEMENTS_HASKELL_RESOURCE_CONSTANTS_H
#define ELEMENTS_HASKELL_RESOURCE_CONSTANTS_H
#include <cstdint>
namespace ElementsDrivechainIdentity {
inline constexpr uint32_t CONSENSUS_MAX_BLOCK_SERIALIZED_SIZE{4000000U};
inline constexpr uint32_t CONSENSUS_MAX_BLOCK_WEIGHT{4000000U};
inline constexpr uint32_t MAX_DRIVECHAIN_DEPOSITS_PER_BLOCK{64U};
inline constexpr int ALPHA_PEGIN_ONE_CONFIRMATION_HEIGHT{64};
inline constexpr uint32_t DEPOSIT_ADDRESS_LIMIT{128U};
inline constexpr unsigned char DEPOSIT_MARKER[]{100,114,105,118,101,99,104,97,105,110,45,100,101,112,111,115,105,116,45,118,50};
inline constexpr unsigned char LEGACY_DEPOSIT_MARKER[]{100,114,105,118,101,99,104,97,105,110,45,100,101,112,111,115,105,116,45,118,49};
inline constexpr unsigned char LEGACY_DEPOSIT_LAYOUT[]{0,1,2,3,255,4};
inline constexpr unsigned char NATIVE_DEPOSIT_LAYOUT[]{0,1,2,3,254,4,5,6};
inline constexpr unsigned char EVIDENCE_DEPOSIT_LAYOUT[]{0,1,2,3,254,4,5,6,7,8,9};
}
#endif
