cmake_minimum_required(VERSION 3.25)
project(EmageWasm C CXX)

if (NOT EMSCRIPTEN)
    message(WARNING
            "This project targets Emscripten. Configure a CLion CMake profile "
            "that uses emsdk's Emscripten.cmake toolchain file, or builds will "
            "just produce a native binary instead of a .wasm/.js pair.")
endif ()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Disable unneeded OpenJPEG features for lean WebAssembly compilation
set(BUILD_CODEC OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/openjpeg)

# JPSEC (Part 8) SEC/INSEC marker parsing is gated behind USE_JPSEC in the
# vendored openjp2; the read handlers themselves live in sec_marker.cc.
target_compile_definitions(openjp2 PRIVATE USE_JPSEC)

# Minimal vendored Mbed TLS (third_party/mbedtls) providing AES-256-CTR for the
# JPSEC SEC marker and SHA3-256 for the level-key cascade. Only the AES block
# cipher + CTR mode and the SHA3 module are enabled via the trimmed
# include/mbedtls/mbedtls_config.h; we compile just the sources that back them.
set(MBEDTLS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls/include")
set(MBEDTLS_LIBRARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls/library")
set(MBEDTLS_SOURCES
        "${MBEDTLS_LIBRARY_DIR}/aes.c"
        "${MBEDTLS_LIBRARY_DIR}/sha3.c"
        "${MBEDTLS_LIBRARY_DIR}/platform_util.c"
)

# Shared link flags for both WASM binaries
set(EMSCRIPTEN_COMMON_FLAGS
        "--bind"
        "-sMODULARIZE=1"
        "-sALLOW_MEMORY_GROWTH=1"
        "-sENVIRONMENT=web"
        "-sNO_EXIT_RUNTIME=1"
        "-sEXPORTED_FUNCTIONS=_malloc,_free"
        "-sEXPORTED_RUNTIME_METHODS=HEAPU8,stackSave,stackRestore,getExceptionMessage,decrementExceptionRefcount"
        # Surface C++ exceptions as catchable JS errors instead of abort()ing the
        # whole module when a decode/encode fails (e.g. a partial layer window
        # that OpenJPEG rejects). Costs a little size; keeps the page alive.
        "-sDISABLE_EXCEPTION_CATCHING=0"
        "-O3"
)

# ==============================================================================
# 1. ENCODER TARGET (EmageWasmEncoder.js / EmageWasmEncoder.wasm)
# ==============================================================================
add_executable(EmageWasmEncoder encoder_bindings.cc sec_marker.cc jpsec_aes.c ${MBEDTLS_SOURCES})

target_include_directories(EmageWasmEncoder PRIVATE
        third_party/openjpeg/src/lib/openjp2
        ${CMAKE_CURRENT_BINARY_DIR}/third_party/openjpeg/src/lib/openjp2
        ${MBEDTLS_INCLUDE_DIR}
        ${MBEDTLS_LIBRARY_DIR}
)

target_link_libraries(EmageWasmEncoder PRIVATE openjp2)

if (EMSCRIPTEN)
    target_link_options(EmageWasmEncoder PRIVATE
            ${EMSCRIPTEN_COMMON_FLAGS}
            "-sEXPORT_NAME=J2KEncoder"
    )
    set_target_properties(EmageWasmEncoder PROPERTIES
            SUFFIX ".js"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif ()

# ==============================================================================
# 2. DECODER TARGET (EmageWasmDecoder.js / EmageWasmDecoder.wasm)
# ==============================================================================
add_executable(EmageWasmDecoder decoder_bindings.cc sec_marker.cc jpsec_aes.c ${MBEDTLS_SOURCES})

target_include_directories(EmageWasmDecoder PRIVATE
        third_party/openjpeg/src/lib/openjp2
        ${CMAKE_CURRENT_BINARY_DIR}/third_party/openjpeg/src/lib/openjp2
        ${MBEDTLS_INCLUDE_DIR}
        ${MBEDTLS_LIBRARY_DIR}
)

target_link_libraries(EmageWasmDecoder PRIVATE openjp2)

if (EMSCRIPTEN)
    target_link_options(EmageWasmDecoder PRIVATE
            ${EMSCRIPTEN_COMMON_FLAGS}
            "-sEXPORT_NAME=J2KDecoder"
    )
    set_target_properties(EmageWasmDecoder PROPERTIES
            SUFFIX ".js"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif ()

# ==============================================================================
# 3. PUBLISH TO SERVER (../RiderProjects/Emage/Emage/wwwroot/wasm)
# ==============================================================================
# Publish each built .js/.wasm pair to the server static assets.
set(EMAGE_SERVER_WASM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../RiderProjects/Emage/Emage/wwwroot/wasm" CACHE PATH "Server WASM asset directory")

if (EMSCRIPTEN)
    add_custom_command(TARGET EmageWasmEncoder POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${EMAGE_SERVER_WASM_DIR}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_BINARY_DIR}/EmageWasmEncoder.js"
            "${CMAKE_BINARY_DIR}/EmageWasmEncoder.wasm"
            "${EMAGE_SERVER_WASM_DIR}/"
            COMMENT "Publishing EmageWasmEncoder bundle to ${EMAGE_SERVER_WASM_DIR}")

    add_custom_command(TARGET EmageWasmDecoder POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${EMAGE_SERVER_WASM_DIR}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_BINARY_DIR}/EmageWasmDecoder.js"
            "${CMAKE_BINARY_DIR}/EmageWasmDecoder.wasm"
            "${EMAGE_SERVER_WASM_DIR}/"
            COMMENT "Publishing EmageWasmDecoder bundle to ${EMAGE_SERVER_WASM_DIR}")
endif ()