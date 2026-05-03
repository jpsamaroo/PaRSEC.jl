# C type aliases used in macro constant definitions
# These are needed because Clang.jl macros emit C type names as-is
const uint8_t = UInt8
const uint16_t = UInt16
const uint32_t = UInt32
const uint64_t = UInt64
const int8_t = Int8
const int16_t = Int16
const int32_t = Int32
const int64_t = Int64
const uintptr_t = UInt == UInt64 ? UInt64 : UInt32
const intptr_t = Int == Int64 ? Int64 : Int32

# C standard limit macros from <limits.h> and <stdint.h>
const INT_MAX = typemax(Int32)
const INT_MIN = typemin(Int32)
const UINT_MAX = typemax(UInt32)
const LONG_MAX = typemax(Clong)
const LONG_MIN = typemin(Clong)
const ULONG_MAX = typemax(Culong)
const INT8_MAX = typemax(Int8)
const INT16_MAX = typemax(Int16)
const INT32_MAX = typemax(Int32)
const INT64_MAX = typemax(Int64)
const UINT8_MAX = typemax(UInt8)
const UINT16_MAX = typemax(UInt16)
const UINT32_MAX = typemax(UInt32)
const UINT64_MAX = typemax(UInt64)
const SIZE_MAX = typemax(Csize_t)
