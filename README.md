# CosFPSI: Efficient Cosine-Threshold Fuzzy PSI for Privacy-Preserving Face Recognition over High-Dimensional Embeddings

This repository contains the core implementation of the many-to-many cosine-threshold fuzzy private set intersection protocol described in the paper.

## Protocol

The protocol evaluates all query-candidate pairs in one global execution:

1. **TPCR candidate recovery.** SimHash fingerprints are divided into blocks. Batched EC-OPRF and RB-OKVS recover block-level evidence under temporary opaque handles. TPCR aggregates this evidence, applies the Hamming lower-bound test, and opens each distinct surviving handle once to recover its candidate and BFV pack location.
2. **CPSS packed scoring.** Sender vectors are fixed-point encoded and stored in reusable BFV ciphertext packs. The retained relation schedules queries across candidate lanes. BFV SIMD evaluation computes the integer inner products, and masking converts every score into additive shares modulo the BFV plaintext modulus.
3. **Exact verification.** A batched Yao circuit reconstructs each shared score modulo the BFV plaintext modulus, applies centered interpretation, compares it with the public threshold, and combines the result with the validity bit. The receiver obtains the final matching relation.

A cryptographic batch may contain pairs from different queries. The implementation therefore follows the global many-to-many relation rather than repeating a single-query protocol.

## Repository Layout

- `stage1`: TPCR, batched EC-OPRF, RB-OKVS lookup, threshold-aware pruning, and unique-handle opening.
- `stage2`: CPSS database packing, BFV SIMD scoring, additive masking, and ciphertext sanitization.
- `stage3`: batched Yao comparison with libOTe input transfer.
- `pipeline`: end-to-end protocol orchestration and metrics.
- `apps/protocol_example.cpp`: minimal many-to-many example.
- `apps/run_dataset.cpp`: dataset runner for correctness, runtime, communication, and TPCR/CPSS statistics.
- `data/lfw`: the 512-dimensional ArcFace feature subset used by the experiments. Original face images are not included.

Third-party source trees, generated results, model weights, and build artifacts are not included.

## Dependencies

- CMake 3.24 or newer and a C++20 compiler
- OpenSSL
- OpenFHE with BFV support
- libOTe and cryptoTools
- RB-OKVS and its matching hash-adapter source

## Build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DOpenFHE_DIR=<openfhe-config-dir> `
  -DlibOTe_DIR=<libote-config-dir> `
  -DRBOKVS_SOURCE_DIR=<rbokvs-source-dir> `
  -DBLAKE3_SOURCE_DIR=<rbokvs-hash-adapter-dir>
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Run

```powershell
.\build\Release\protocol_example.exe

.\build\Release\run_dataset.exe `
  --dataset-dir .\data\lfw `
  --output .\output\lfw_results.json `
  --simhash-bits 32 --blocks 8 `
  --warmups 1 --repeats 3
```

The TPCR pruning ablation uses the same protocol and disables only the lower-bound pruning step:

```powershell
.\build\Release\run_dataset.exe `
  --dataset-dir .\data\lfw `
  --output .\output\lfw_without_pruning.json `
  --simhash-bits 32 --blocks 8 `
  --disable-threshold-pruning
```
