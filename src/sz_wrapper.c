#define SZ_DYNAMIC_DISPATCH 0
#define SZ_USE_MISALIGNED_LOADS 1
#define SZ_USE_HASWELL 0
#define SZ_USE_SKYLAKE 0
#define SZ_USE_ICE 0
#define SZ_USE_WESTMERE 0
#define SZ_USE_NEON 0
#define SZ_USE_SVE 0
#define SZ_USE_SVE2 0
#define SZ_USE_X86_AVX512 0
#define SZ_USE_X86_AVX2 0
#define SZ_USE_ARM_NEON 0
#define SZ_USE_ARM_SVE 0
#include "stringzilla/find.h"

const char* sz_find_wrapper(const char* haystack, size_t h_len, const char* needle, size_t n_len) {
    return sz_find_serial(haystack, h_len, needle, n_len);
}
