cmake_minimum_required(VERSION 3.24)
project(CosineThresholdFPSI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RBOKVS_SOURCE_DIR "" CACHE PATH "Directory containing rb_okvs.cpp and rb_okvs.h")
set(BLAKE3_SOURCE_DIR "" CACHE PATH "Directory containing the RB-OKVS SHA-256 hash adapter: blake3_compat.cpp and blake3.h")
if(NOT EXISTS "${RBOKVS_SOURCE_DIR}/rb_okvs.cpp" OR NOT EXISTS "${RBOKVS_SOURCE_DIR}/rb_okvs.h")
  message(FATAL_ERROR "Set RBOKVS_SOURCE_DIR to an external RB-OKVS source directory")
endif()
if(NOT EXISTS "${BLAKE3_SOURCE_DIR}/blake3_compat.cpp" OR NOT EXISTS "${BLAKE3_SOURCE_DIR}/blake3.h")
  message(FATAL_ERROR "Set BLAKE3_SOURCE_DIR to the matching RB-OKVS hash-adapter source directory")
endif()

find_package(OpenSSL REQUIRED)
find_package(OpenFHE CONFIG REQUIRED)
find_package(libOTe CONFIG REQUIRED)

if(TARGET oc::cryptoTools)
  set(CRYPTOTOOLS_TARGET oc::cryptoTools)
elseif(TARGET cryptoTools)
  set(CRYPTOTOOLS_TARGET cryptoTools)
else()
  message(FATAL_ERROR "cryptoTools target was not exported by libOTe")
endif()
if(TARGET oc::libOTe)
  set(LIBOTE_TARGET oc::libOTe)
elseif(TARGET libOTe)
  set(LIBOTE_TARGET libOTe)
else()
  message(FATAL_ERROR "libOTe target was not found")
endif()

add_library(rbokvs_external STATIC
  "${RBOKVS_SOURCE_DIR}/rb_okvs.cpp"
  "${BLAKE3_SOURCE_DIR}/blake3_compat.cpp")
target_include_directories(rbokvs_external PUBLIC "${RBOKVS_SOURCE_DIR}" "${BLAKE3_SOURCE_DIR}")
target_compile_definitions(rbokvs_external PRIVATE SIMFHE_RBOKVS_DISABLE_RISTRETTO=1)
target_compile_features(rbokvs_external PUBLIC cxx_std_20)
target_link_libraries(rbokvs_external PUBLIC ${CRYPTOTOOLS_TARGET} OpenSSL::Crypto)

add_library(fpsi_common INTERFACE)
target_include_directories(fpsi_common INTERFACE common/include)

add_library(fpsi_adapters STATIC adapters/src/rbokvs_adapter.cpp)
target_include_directories(fpsi_adapters PUBLIC adapters/include)
target_compile_definitions(fpsi_adapters PRIVATE SIMFHE_RBOKVS_DISABLE_RISTRETTO=1)
target_link_libraries(fpsi_adapters PUBLIC fpsi_common rbokvs_external)

add_library(fpsi_stage1 STATIC
  stage1/src/candidate_payload.cpp
  stage1/src/oprf_provider.cpp
  stage1/src/p256_hash_to_curve.cpp
  stage1/src/query_preprocessor.cpp
  stage1/src/stage1_index_builder.cpp
  stage1/src/threshold_parameterization.cpp)
target_include_directories(fpsi_stage1 PUBLIC stage1/include)
target_compile_definitions(fpsi_stage1 PUBLIC CTFPSI_STAGE1_HAS_OPENSSL=1)
target_link_libraries(fpsi_stage1 PUBLIC fpsi_common fpsi_adapters OpenSSL::Crypto)

add_library(fpsi_stage2 STATIC stage2/src/exact_he_masked_score.cpp)
# OpenFHE's installed serialization headers are compiled in C++17 mode.
set_target_properties(fpsi_stage2 PROPERTIES CXX_STANDARD 17)
target_include_directories(fpsi_stage2 PUBLIC stage2/include)
target_compile_definitions(fpsi_stage2 PUBLIC CTFPSI_HAS_OPENFHE=1)
target_compile_definitions(fpsi_stage2 PRIVATE _USE_MATH_DEFINES)
if(TARGET OpenFHE::openfhe)
  target_link_libraries(fpsi_stage2 PUBLIC fpsi_common OpenFHE::openfhe OpenSSL::Crypto)
elseif(TARGET openfhe)
  target_link_libraries(fpsi_stage2 PUBLIC fpsi_common openfhe OpenSSL::Crypto)
else()
  if(DEFINED OpenFHE_INCLUDE_DIRS)
    target_include_directories(fpsi_stage2 PUBLIC ${OpenFHE_INCLUDE_DIRS})
  elseif(DEFINED OpenFHE_INCLUDE)
    get_filename_component(OpenFHE_INCLUDE_PARENT "${OpenFHE_INCLUDE}" DIRECTORY)
    target_include_directories(fpsi_stage2 PUBLIC
      ${OpenFHE_INCLUDE}
      ${OpenFHE_INCLUDE_PARENT}
      ${OpenFHE_INCLUDE}/core
      ${OpenFHE_INCLUDE}/pke
      ${OpenFHE_INCLUDE}/binfhe)
  endif()
  target_link_libraries(fpsi_stage2 PUBLIC fpsi_common ${OpenFHE_LIBRARIES} OpenSSL::Crypto)
endif()

add_library(fpsi_stage3 STATIC
  stage3/src/yao_circuit_spec.cpp
  stage3/src/yao_compare.cpp
  stage3/src/yao_gate_hash.cpp
  stage3/src/yao_half_gates.cpp
  stage3/src/yao_labels.cpp
  stage3/src/gc_backend_adapter.cpp
  stage3/src/protocol_context.cpp
  stage3/src/protocol_messages.cpp
  stage3/src/transcript.cpp
  stage3/src/transport.cpp)
target_include_directories(fpsi_stage3 PUBLIC stage3/include)
target_compile_definitions(fpsi_stage3 PUBLIC
  CTFPSI_HAS_CRYPTOTOOLS=1 CTFPSI_HAS_LIBOTE=1
  CTFPSI_HAS_LIBOTE_CMAKE_VISIBLE=1
  CTFPSI_HAS_LIBOTE_TARGET_OC_LIBOTE=1
  CTFPSI_HAS_LIBOTE_TARGET_OC_CRYPTOTOOLS=1
  CTFPSI_HAS_LIBOTE_TARGET_ANY=1)
target_compile_features(fpsi_stage3 PUBLIC cxx_std_20)
target_link_libraries(fpsi_stage3 PUBLIC fpsi_common ${LIBOTE_TARGET} ${CRYPTOTOOLS_TARGET} OpenSSL::Crypto)

add_library(fpsi_pipeline STATIC pipeline/src/cosine_threshold_protocol.cpp)
target_include_directories(fpsi_pipeline PUBLIC pipeline/include)
target_link_libraries(fpsi_pipeline PUBLIC fpsi_common fpsi_adapters fpsi_stage1 fpsi_stage2 fpsi_stage3)
if(WIN32)
  target_link_libraries(fpsi_pipeline PUBLIC Psapi)
endif()

add_executable(run_dataset apps/run_dataset.cpp apps/dataset_io.cpp)
target_include_directories(run_dataset PRIVATE apps)
target_link_libraries(run_dataset PRIVATE fpsi_pipeline)

