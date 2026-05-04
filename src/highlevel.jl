# ─────────────────────────────────────────────────────────────────────────────
# highlevel.jl — High-level DTD task spawning interface
#
# Included from src/PaRSEC.jl.  Provides:
#   PaRSEC.taskpool(f, ctx)
#   PaRSEC.@spawn tp "name" f(INOUT(A), IN(B), VAL(i))
#   PaRSEC.VAL, PaRSEC.IN, PaRSEC.OUT, PaRSEC.INOUT
# ─────────────────────────────────────────────────────────────────────────────

using Libdl: dlopen, dlsym
using MPI

# ─── Function-pointer handles for variadic C calls ───────────────────────────

const _hl_lp_handle       = Ref{Ptr{Cvoid}}(C_NULL)
const _hl_insert_task_ptr = Ref{Ptr{Cvoid}}(C_NULL)
const _hl_unpack_args_ptr = Ref{Ptr{Cvoid}}(C_NULL)

function _hl_init()
    _hl_lp_handle[]       = dlopen(PaRSEC_jll.libparsec_path)
    _hl_insert_task_ptr[] = dlsym(_hl_lp_handle[], :parsec_dtd_insert_task)
    _hl_unpack_args_ptr[] = dlsym(_hl_lp_handle[], :parsec_dtd_unpack_args)
end

# ═══════════════════════════════════════════════════════════════════════════════
# Argument wrappers
# ═══════════════════════════════════════════════════════════════════════════════

struct ValArg{T};   val::T; end
struct InArg{T};    val::T; end
struct OutArg{T};   val::T; end
struct InOutArg{T}; val::T; end

"""    VAL(x) — pack scalar `x` by value (must be isbits)."""
VAL(x) = (isbitstype(typeof(x)) || error("VAL requires isbits, got $(typeof(x))"); ValArg(x))

"""    IN(x) — pass `x` by reference, read-only dependency."""
IN(x) = InArg(x)

"""    OUT(x) — pass `x` by reference, write-only dependency."""
OUT(x) = OutArg(x)

"""    INOUT(x) — pass `x` by reference, read-write dependency."""
INOUT(x) = InOutArg(x)

_unwrap(a::ValArg)   = a.val
_unwrap(a::InArg)    = a.val
_unwrap(a::OutArg)   = a.val
_unwrap(a::InOutArg) = a.val

_is_val(::ValArg) = true
_is_val(::Union{InArg, OutArg, InOutArg}) = false

# ═══════════════════════════════════════════════════════════════════════════════
# Thread-safe invocation table
# ═══════════════════════════════════════════════════════════════════════════════

const _invocation_table   = Dict{UInt64, Tuple{Any, Tuple}}()
const _invocation_lock    = ReentrantLock()
const _next_invocation_id = Threads.Atomic{UInt64}(0)

function _register_invocation(f, args::Tuple)::UInt64
    id = Threads.atomic_add!(_next_invocation_id, UInt64(1)) + UInt64(1)
    lock(_invocation_lock) do
        _invocation_table[id] = (f, args)
    end
    return id
end

function _consume_invocation(id::UInt64)
    lock(_invocation_lock) do
        entry = _invocation_table[id]
        delete!(_invocation_table, id)
        return entry
    end
end

# ═══════════════════════════════════════════════════════════════════════════════
# Trampoline
# ═══════════════════════════════════════════════════════════════════════════════

# PaRSEC hashes DTD task classes by (hook_function_pointer + flow_count_of_tc).
# VALUE-only tasks share one unpack layout (invocation id + optional VALUE slots).
# Tasks with Array IN/OUT/INOUT use PASSED_BY_REF tiles: unpack is invocation id
# (VALUE) then one void** per flow (see parsec_dtd_unpack_args in insert_function.c).
# Each distinct unpack arity needs its own @cfunction entry point.

function _run_invocation(id::UInt64)
    f, args = _consume_invocation(id)
    try
        f(args...)
    catch e
        @error "Error in task invocation" exception=(e, catch_backtrace())
        return Cint(LibPaRSEC.PARSEC_HOOK_RETURN_ERROR)
    end
    return Cint(LibPaRSEC.PARSEC_HOOK_RETURN_DONE)
end

# Match the @cfunction ABI used by demo.jl (working PaRSEC+Julia): first arg as
# Ptr{Cvoid}, second as Ptr{parsec_task_t}.  Two Ptr{Cvoid} entries mis-compile
# on some Julia versions and corrupt the register/stack layout at the hook site.

const _TT = LibPaRSEC.parsec_task_t
const _ES = LibPaRSEC.parsec_execution_stream_t

function _trampoline_entry_0(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot begin
        @ccall $uap(this_task::Ptr{_TT} ; id_slot::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_1(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_2(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    d2 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 d2 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64}, d2::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_3(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    d2 = Ref{UInt64}(0)
    d3 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 d2 d3 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64}, d2::Ptr{UInt64},
                     d3::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_4(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    d2 = Ref{UInt64}(0)
    d3 = Ref{UInt64}(0)
    d4 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 d2 d3 d4 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64}, d2::Ptr{UInt64},
                     d3::Ptr{UInt64}, d4::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_5(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    d2 = Ref{UInt64}(0)
    d3 = Ref{UInt64}(0)
    d4 = Ref{UInt64}(0)
    d5 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 d2 d3 d4 d5 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64}, d2::Ptr{UInt64},
                     d3::Ptr{UInt64}, d4::Ptr{UInt64}, d5::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_6(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    d2 = Ref{UInt64}(0)
    d3 = Ref{UInt64}(0)
    d4 = Ref{UInt64}(0)
    d5 = Ref{UInt64}(0)
    d6 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 d2 d3 d4 d5 d6 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64}, d2::Ptr{UInt64},
                     d3::Ptr{UInt64}, d4::Ptr{UInt64}, d5::Ptr{UInt64},
                     d6::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_7(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    d2 = Ref{UInt64}(0)
    d3 = Ref{UInt64}(0)
    d4 = Ref{UInt64}(0)
    d5 = Ref{UInt64}(0)
    d6 = Ref{UInt64}(0)
    d7 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 d2 d3 d4 d5 d6 d7 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64}, d2::Ptr{UInt64},
                     d3::Ptr{UInt64}, d4::Ptr{UInt64}, d5::Ptr{UInt64},
                     d6::Ptr{UInt64}, d7::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _trampoline_entry_8(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    d1 = Ref{UInt64}(0)
    d2 = Ref{UInt64}(0)
    d3 = Ref{UInt64}(0)
    d4 = Ref{UInt64}(0)
    d5 = Ref{UInt64}(0)
    d6 = Ref{UInt64}(0)
    d7 = Ref{UInt64}(0)
    d8 = Ref{UInt64}(0)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot d1 d2 d3 d4 d5 d6 d7 d8 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, d1::Ptr{UInt64}, d2::Ptr{UInt64},
                     d3::Ptr{UInt64}, d4::Ptr{UInt64}, d5::Ptr{UInt64},
                     d6::Ptr{UInt64}, d7::Ptr{UInt64}, d8::Ptr{UInt64})::Cvoid
    end
    return _run_invocation(id_slot[])
end

# ─── Flow unpackers (invocation id + N void** slots for INPUT/OUTPUT/INOUT) ──

function _flow_trampoline_1(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _flow_trampoline_2(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    g2 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 g2 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}}, g2::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _flow_trampoline_3(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    g2 = Ref{Ptr{Cvoid}}(C_NULL)
    g3 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 g2 g3 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}}, g2::Ptr{Ptr{Cvoid}},
                     g3::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _flow_trampoline_4(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    g2 = Ref{Ptr{Cvoid}}(C_NULL)
    g3 = Ref{Ptr{Cvoid}}(C_NULL)
    g4 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 g2 g3 g4 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}}, g2::Ptr{Ptr{Cvoid}},
                     g3::Ptr{Ptr{Cvoid}}, g4::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _flow_trampoline_5(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    g2 = Ref{Ptr{Cvoid}}(C_NULL)
    g3 = Ref{Ptr{Cvoid}}(C_NULL)
    g4 = Ref{Ptr{Cvoid}}(C_NULL)
    g5 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 g2 g3 g4 g5 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}}, g2::Ptr{Ptr{Cvoid}},
                     g3::Ptr{Ptr{Cvoid}}, g4::Ptr{Ptr{Cvoid}}, g5::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _flow_trampoline_6(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    g2 = Ref{Ptr{Cvoid}}(C_NULL)
    g3 = Ref{Ptr{Cvoid}}(C_NULL)
    g4 = Ref{Ptr{Cvoid}}(C_NULL)
    g5 = Ref{Ptr{Cvoid}}(C_NULL)
    g6 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 g2 g3 g4 g5 g6 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}}, g2::Ptr{Ptr{Cvoid}},
                     g3::Ptr{Ptr{Cvoid}}, g4::Ptr{Ptr{Cvoid}}, g5::Ptr{Ptr{Cvoid}},
                     g6::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _flow_trampoline_7(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    g2 = Ref{Ptr{Cvoid}}(C_NULL)
    g3 = Ref{Ptr{Cvoid}}(C_NULL)
    g4 = Ref{Ptr{Cvoid}}(C_NULL)
    g5 = Ref{Ptr{Cvoid}}(C_NULL)
    g6 = Ref{Ptr{Cvoid}}(C_NULL)
    g7 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 g2 g3 g4 g5 g6 g7 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}}, g2::Ptr{Ptr{Cvoid}},
                     g3::Ptr{Ptr{Cvoid}}, g4::Ptr{Ptr{Cvoid}}, g5::Ptr{Ptr{Cvoid}},
                     g6::Ptr{Ptr{Cvoid}}, g7::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

function _flow_trampoline_8(es::Ptr{_ES}, this_task::Ptr{_TT})
    Base.donotdelete(es)
    id_slot = Ref{UInt64}(0)
    g1 = Ref{Ptr{Cvoid}}(C_NULL)
    g2 = Ref{Ptr{Cvoid}}(C_NULL)
    g3 = Ref{Ptr{Cvoid}}(C_NULL)
    g4 = Ref{Ptr{Cvoid}}(C_NULL)
    g5 = Ref{Ptr{Cvoid}}(C_NULL)
    g6 = Ref{Ptr{Cvoid}}(C_NULL)
    g7 = Ref{Ptr{Cvoid}}(C_NULL)
    g8 = Ref{Ptr{Cvoid}}(C_NULL)
    uap = _hl_unpack_args_ptr[]
    GC.@preserve id_slot g1 g2 g3 g4 g5 g6 g7 g8 begin
        @ccall $uap(this_task::Ptr{_TT} ;
                     id_slot::Ptr{UInt64}, g1::Ptr{Ptr{Cvoid}}, g2::Ptr{Ptr{Cvoid}},
                     g3::Ptr{Ptr{Cvoid}}, g4::Ptr{Ptr{Cvoid}}, g5::Ptr{Ptr{Cvoid}},
                     g6::Ptr{Ptr{Cvoid}}, g7::Ptr{Ptr{Cvoid}}, g8::Ptr{Ptr{Cvoid}})::Cvoid
    end
    return _run_invocation(id_slot[])
end

# @cfunction pointers must be created at runtime (__init__), not baked into the
# pkgimage — otherwise Julia can record invalid / stale code pointers and PaRSEC
# jumps into garbage when executing tasks (segfault in __parsec_execute).
const _trampoline_cfn_by_nargs = Ref{NTuple{9,Ptr{Cvoid}}}(ntuple(_ -> Ptr{Cvoid}(0), 9))
const _trampoline_flow_cfn_by_nargs = Ref{NTuple{9,Ptr{Cvoid}}}(ntuple(_ -> Ptr{Cvoid}(0), 9))

function _init_trampoline_cfunctions!()
    _trampoline_cfn_by_nargs[] = (
        @cfunction(_trampoline_entry_0, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_1, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_2, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_3, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_4, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_5, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_6, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_7, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_trampoline_entry_8, Cint, (Ptr{_ES}, Ptr{_TT})),
    )
    _trampoline_flow_cfn_by_nargs[] = (
        @cfunction(_trampoline_entry_0, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_1, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_2, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_3, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_4, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_5, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_6, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_7, Cint, (Ptr{_ES}, Ptr{_TT})),
        @cfunction(_flow_trampoline_8, Cint, (Ptr{_ES}, Ptr{_TT})),
    )
    return nothing
end

# ═══════════════════════════════════════════════════════════════════════════════
# DTD data collection for Array dependencies (PASSED_BY_REF + parsec_dtd_tile_of)
# ═══════════════════════════════════════════════════════════════════════════════

const _DC = LibPaRSEC.parsec_data_collection_t
const _data_dist_init_lock = ReentrantLock()
const _data_dist_inited = Ref(false)

function _ensure_data_dist_init!()
    lock(_data_dist_init_lock) do
        if !_data_dist_inited[]
            LibPaRSEC.parsec_data_dist_init()
            _data_dist_inited[] = true
        end
    end
    return nothing
end

mutable struct _DtdArraySession
    ctx::Ptr{LibPaRSEC.parsec_context_s}
    dc_buf::Vector{UInt8}
    data_by_key::Dict{UInt64, Ptr{LibPaRSEC.parsec_data_t}}
    pinned::Vector{Any}
    myrank::UInt32
    nodes::UInt32
    mpi_multi::Bool
end

function _dtd_session_ptr(s::_DtdArraySession)
    return Ptr{_DC}(pointer(s.dc_buf))
end

const _dtd_array_session = Ref{Union{Nothing,_DtdArraySession}}(nothing)

function _jl_rank_of_key(_d::Ptr{_DC}, key::UInt64)::UInt32
    s = _dtd_array_session[]
    (s === nothing) && return UInt32(0)
    return s.myrank
end

function _jl_rank_of(_d::Ptr{_DC}, key::UInt64)::UInt32
    _jl_rank_of_key(_d, key)
end

function _jl_data_of_key(_d::Ptr{_DC}, key::UInt64)::Ptr{LibPaRSEC.parsec_data_t}
    s = _dtd_array_session[]
    (s === nothing) && return Ptr{LibPaRSEC.parsec_data_t}(0)
    return get(s.data_by_key, key, Ptr{LibPaRSEC.parsec_data_t}(0))
end

function _jl_data_of(_d::Ptr{_DC}, key::UInt64)::Ptr{LibPaRSEC.parsec_data_t}
    _jl_data_of_key(_d, key)
end

function _jl_data_key(_d::Ptr{_DC}, key::UInt64)::UInt64
    key
end

function _jl_vpid_of_key(_d::Ptr{_DC}, key::UInt64)::Int32
    Int32(0)
end

function _jl_vpid_of(_d::Ptr{_DC}, key::UInt64)::Int32
    Int32(0)
end

function _jl_key_to_string(_d::Ptr{_DC}, key::UInt64, buffer::Ptr{Cchar}, buffer_size::UInt32)::Cint
    buffer == C_NULL && return Cint(0)
    sz = Int(buffer_size)
    sz <= 0 && return Cint(0)
    digits = string(key)
    n = min(length(digits), sz - 1)
    for i in 1:n
        unsafe_store!(Ptr{UInt8}(buffer + (i - 1)), UInt8(codeunit(digits, i)))
    end
    unsafe_store!(Ptr{UInt8}(buffer + n), UInt8(0))
    return Cint(n)
end

const _cfn_rank_of_key = Ref{Ptr{Cvoid}}(C_NULL)
const _cfn_rank_of = Ref{Ptr{Cvoid}}(C_NULL)
const _cfn_data_of_key = Ref{Ptr{Cvoid}}(C_NULL)
const _cfn_data_of = Ref{Ptr{Cvoid}}(C_NULL)
const _cfn_data_key = Ref{Ptr{Cvoid}}(C_NULL)
const _cfn_vpid_of_key = Ref{Ptr{Cvoid}}(C_NULL)
const _cfn_vpid_of = Ref{Ptr{Cvoid}}(C_NULL)
const _cfn_key_to_string = Ref{Ptr{Cvoid}}(C_NULL)

function _init_dtd_dc_callbacks!()
    _cfn_rank_of_key[] = @cfunction(_jl_rank_of_key, UInt32, (Ptr{_DC}, UInt64))
    _cfn_rank_of[] = @cfunction(_jl_rank_of, UInt32, (Ptr{_DC}, UInt64))
    _cfn_data_of_key[] = @cfunction(_jl_data_of_key, Ptr{LibPaRSEC.parsec_data_t}, (Ptr{_DC}, UInt64))
    _cfn_data_of[] = @cfunction(_jl_data_of, Ptr{LibPaRSEC.parsec_data_t}, (Ptr{_DC}, UInt64))
    _cfn_data_key[] = @cfunction(_jl_data_key, UInt64, (Ptr{_DC}, UInt64))
    _cfn_vpid_of_key[] = @cfunction(_jl_vpid_of_key, Int32, (Ptr{_DC}, UInt64))
    _cfn_vpid_of[] = @cfunction(_jl_vpid_of, Int32, (Ptr{_DC}, UInt64))
    _cfn_key_to_string[] = @cfunction(_jl_key_to_string, Cint, (Ptr{_DC}, UInt64, Ptr{Cchar}, UInt32))
    return nothing
end

const _dc_field_index = Dict{Symbol,Int}(n => i for (i, n) in enumerate(fieldnames(_DC)))

function _poke_dc_fn!(dc::Ptr{_DC}, field::Symbol, fn::Ptr{Cvoid})
    off = fieldoffset(_DC, _dc_field_index[field])
    unsafe_store!(Ptr{Ptr{Cvoid}}(dc + off), fn)
    return nothing
end

function _install_julia_dc_vtable!(dc::Ptr{_DC})
    _poke_dc_fn!(dc, :data_key, _cfn_data_key[])
    _poke_dc_fn!(dc, :rank_of, _cfn_rank_of[])
    _poke_dc_fn!(dc, :rank_of_key, _cfn_rank_of_key[])
    _poke_dc_fn!(dc, :data_of, _cfn_data_of[])
    _poke_dc_fn!(dc, :data_of_key, _cfn_data_of_key[])
    _poke_dc_fn!(dc, :vpid_of, _cfn_vpid_of[])
    _poke_dc_fn!(dc, :vpid_of_key, _cfn_vpid_of_key[])
    _poke_dc_fn!(dc, :key_to_string, _cfn_key_to_string[])
    return nothing
end

function _mpi_rank_nodes_affinity()
    if MPI.Initialized()
        r = Int32(MPI.Comm_rank(MPI.COMM_WORLD))
        n = Int32(MPI.Comm_size(MPI.COMM_WORLD))
        return (UInt32(r), UInt32(n), n > Int32(1))
    end
    return (UInt32(0), UInt32(1), false)
end

function _array_tile_key(a::Array)::UInt64
    UInt64(objectid(a))
end

function _mpi_datatype_for_array(a::Array)
    T = eltype(a)
    isbitstype(T) || error("Array eltype must be isbits for PaRSEC data tiles, got $T")
    return MPI.Datatype(T).val
end

function _ensure_array_tile!(a::Array, dcptr::Ptr{_DC})
    s = _dtd_array_session[]
    (s === nothing) && error("internal: DTD array session not active")
    key = _array_tile_key(a)
    haskey(s.data_by_key, key) && return nothing
    push!(s.pinned, a)
    T = eltype(a)
    nbytes = Csize_t(sizeof(T) * length(a))
    p = Ptr{Cvoid}(pointer(a))
    dtt = _mpi_datatype_for_array(a)
    pdata = LibPaRSEC.parsec_data_create_with_type(dcptr, key, p, nbytes, dtt)
    pdata == C_NULL && error("parsec_data_create_with_type failed")
    s.data_by_key[key] = pdata
    return nothing
end

function _affinity_index(wrapped::Vector)
    for (i, w) in enumerate(wrapped)
        w isa Union{InOutArg, OutArg} && return Int32(i)
    end
    return Int32(1)
end

function _parsec_flow_op(w::Union{InArg, OutArg, InOutArg}, arg_index::Int, s::_DtdArraySession, aff_idx::Int32)
    base = if w isa InArg
        LibPaRSEC.PARSEC_INPUT
    elseif w isa OutArg
        LibPaRSEC.PARSEC_OUTPUT
    else
        LibPaRSEC.PARSEC_INOUT
    end
    op = if s.mpi_multi && Int32(arg_index) == aff_idx
        Cint(base | LibPaRSEC.PARSEC_AFFINITY)
    else
        Cint(base)
    end
    return op
end

# ═══════════════════════════════════════════════════════════════════════════════
# Triplet construction
#
# PaRSEC insert_task variadic triplets:
#   VALUE:  (sizeof(T),    &value,          PARSEC_VALUE)
#   REF:    (PASSED_BY_REF, parsec_dtd_tile_of(dc,key), PARSEC_INPUT/OUTPUT/INOUT)
# ═══════════════════════════════════════════════════════════════════════════════

const _PREF = Cint(Int32(LibPaRSEC.PASSED_BY_REF))

function _make_triplet(wa::ValArg{T}) where T
    r = Ref(wa.val)
    p = Base.unsafe_convert(Ptr{Cvoid}, Ptr{T}(Base.pointer_from_objref(r)))
    return (Cint(sizeof(T)), p, Cint(LibPaRSEC.PARSEC_VALUE), r)
end

function _make_ptr_value_triplet(v)
    p = v isa AbstractArray ? Ptr{Cvoid}(pointer(v)) :
                              Ptr{Cvoid}(Base.pointer_from_objref(v))
    r = Ref(p)
    rp = Base.unsafe_convert(Ptr{Cvoid}, Ptr{Ptr{Cvoid}}(Base.pointer_from_objref(r)))
    return (Cint(sizeof(Ptr{Cvoid})), rp, Cint(LibPaRSEC.PARSEC_VALUE), r)
end

"""Triplet for IN/OUT/INOUT when dependency tracking uses a DTD tile (see insert_function.h)."""
function _make_flow_triplet(w::Union{InArg, OutArg, InOutArg}, a::Array, dcptr::Ptr{_DC},
                            arg_index::Int, s::_DtdArraySession, aff_idx::Int32)
    _ensure_array_tile!(a, dcptr)
    key = _array_tile_key(a)
    tile = LibPaRSEC.parsec_dtd_tile_of(dcptr, key)
    tile == C_NULL && error("parsec_dtd_tile_of returned NULL")
    op = _parsec_flow_op(w, arg_index, s, aff_idx)
    return (_PREF, Ptr{Cvoid}(tile), op, nothing)
end

const _preserve_dummy = Ref{UInt64}(0)
_ph(h) = h === nothing ? _preserve_dummy : h

function _triplet_for_arg(w, dcptr::Ptr{_DC}, arg_index::Int, s::Union{Nothing,_DtdArraySession},
                          use_flow::Bool, aff_idx::Int32)
    w isa ValArg && return _make_triplet(w)
    if use_flow && dcptr != C_NULL && s !== nothing && _unwrap(w) isa Array
        return _make_flow_triplet(w, _unwrap(w)::Array, dcptr, arg_index, s::_DtdArraySession, aff_idx)
    end
    return _make_ptr_value_triplet(_unwrap(w))
end

_all_array_flow_wrappers(wrapped::Vector) =
    all(w -> w isa Union{InArg, OutArg, InOutArg} && _unwrap(w) isa Array &&
             isbitstype(eltype(_unwrap(w)::Array)), wrapped)

# ═══════════════════════════════════════════════════════════════════════════════
# Task insertion — fixed-arity dispatchers
# ═══════════════════════════════════════════════════════════════════════════════

function _do_insert_task(tp::Ptr{LibPaRSEC.parsec_taskpool_t}, name::String,
                         invocation_id::UInt64, wrapped_args::Vector)
    n = length(wrapped_args)
    n > 8 && error("@spawn supports at most 8 arguments (got $n)")

    sess = _dtd_array_session[]
    use_flow = sess !== nothing && _all_array_flow_wrappers(wrapped_args)
    dcptr = use_flow ? _dtd_session_ptr(sess) : Ptr{_DC}(C_NULL)
    aff_idx = use_flow ? _affinity_index(wrapped_args) : Int32(1)
    cfn = (use_flow ? _trampoline_flow_cfn_by_nargs[] : _trampoline_cfn_by_nargs[])[n + 1]

    id_ref = Ref(invocation_id)
    itp = _hl_insert_task_ptr[]
    DEV = Cint(LibPaRSEC.PARSEC_DEV_CPU)
    PVAL = Cint(LibPaRSEC.PARSEC_VALUE)
    PEND = Cint(LibPaRSEC.PARSEC_DTD_ARG_END)
    id_sz = Cint(sizeof(UInt64))

    if n == 0
        GC.@preserve id_ref begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 1
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        h1p = _ph(h1)
        GC.@preserve id_ref h1p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 2
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        e1_2, e2_2, e3_2, h2 = _triplet_for_arg(wrapped_args[2], dcptr, 2, sess, use_flow, aff_idx)
        h1p, h2p = _ph(h1), _ph(h2)
        GC.@preserve id_ref h1p h2p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                e1_2::Cint, e2_2::Ptr{Cvoid}, e3_2::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 3
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        e1_2, e2_2, e3_2, h2 = _triplet_for_arg(wrapped_args[2], dcptr, 2, sess, use_flow, aff_idx)
        e1_3, e2_3, e3_3, h3 = _triplet_for_arg(wrapped_args[3], dcptr, 3, sess, use_flow, aff_idx)
        h1p, h2p, h3p = _ph(h1), _ph(h2), _ph(h3)
        GC.@preserve id_ref h1p h2p h3p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                e1_2::Cint, e2_2::Ptr{Cvoid}, e3_2::Cint,
                e1_3::Cint, e2_3::Ptr{Cvoid}, e3_3::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 4
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        e1_2, e2_2, e3_2, h2 = _triplet_for_arg(wrapped_args[2], dcptr, 2, sess, use_flow, aff_idx)
        e1_3, e2_3, e3_3, h3 = _triplet_for_arg(wrapped_args[3], dcptr, 3, sess, use_flow, aff_idx)
        e1_4, e2_4, e3_4, h4 = _triplet_for_arg(wrapped_args[4], dcptr, 4, sess, use_flow, aff_idx)
        h1p, h2p, h3p, h4p = _ph(h1), _ph(h2), _ph(h3), _ph(h4)
        GC.@preserve id_ref h1p h2p h3p h4p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                e1_2::Cint, e2_2::Ptr{Cvoid}, e3_2::Cint,
                e1_3::Cint, e2_3::Ptr{Cvoid}, e3_3::Cint,
                e1_4::Cint, e2_4::Ptr{Cvoid}, e3_4::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 5
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        e1_2, e2_2, e3_2, h2 = _triplet_for_arg(wrapped_args[2], dcptr, 2, sess, use_flow, aff_idx)
        e1_3, e2_3, e3_3, h3 = _triplet_for_arg(wrapped_args[3], dcptr, 3, sess, use_flow, aff_idx)
        e1_4, e2_4, e3_4, h4 = _triplet_for_arg(wrapped_args[4], dcptr, 4, sess, use_flow, aff_idx)
        e1_5, e2_5, e3_5, h5 = _triplet_for_arg(wrapped_args[5], dcptr, 5, sess, use_flow, aff_idx)
        h1p, h2p, h3p, h4p, h5p = _ph(h1), _ph(h2), _ph(h3), _ph(h4), _ph(h5)
        GC.@preserve id_ref h1p h2p h3p h4p h5p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                e1_2::Cint, e2_2::Ptr{Cvoid}, e3_2::Cint,
                e1_3::Cint, e2_3::Ptr{Cvoid}, e3_3::Cint,
                e1_4::Cint, e2_4::Ptr{Cvoid}, e3_4::Cint,
                e1_5::Cint, e2_5::Ptr{Cvoid}, e3_5::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 6
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        e1_2, e2_2, e3_2, h2 = _triplet_for_arg(wrapped_args[2], dcptr, 2, sess, use_flow, aff_idx)
        e1_3, e2_3, e3_3, h3 = _triplet_for_arg(wrapped_args[3], dcptr, 3, sess, use_flow, aff_idx)
        e1_4, e2_4, e3_4, h4 = _triplet_for_arg(wrapped_args[4], dcptr, 4, sess, use_flow, aff_idx)
        e1_5, e2_5, e3_5, h5 = _triplet_for_arg(wrapped_args[5], dcptr, 5, sess, use_flow, aff_idx)
        e1_6, e2_6, e3_6, h6 = _triplet_for_arg(wrapped_args[6], dcptr, 6, sess, use_flow, aff_idx)
        h1p, h2p, h3p, h4p, h5p, h6p = _ph(h1), _ph(h2), _ph(h3), _ph(h4), _ph(h5), _ph(h6)
        GC.@preserve id_ref h1p h2p h3p h4p h5p h6p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                e1_2::Cint, e2_2::Ptr{Cvoid}, e3_2::Cint,
                e1_3::Cint, e2_3::Ptr{Cvoid}, e3_3::Cint,
                e1_4::Cint, e2_4::Ptr{Cvoid}, e3_4::Cint,
                e1_5::Cint, e2_5::Ptr{Cvoid}, e3_5::Cint,
                e1_6::Cint, e2_6::Ptr{Cvoid}, e3_6::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 7
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        e1_2, e2_2, e3_2, h2 = _triplet_for_arg(wrapped_args[2], dcptr, 2, sess, use_flow, aff_idx)
        e1_3, e2_3, e3_3, h3 = _triplet_for_arg(wrapped_args[3], dcptr, 3, sess, use_flow, aff_idx)
        e1_4, e2_4, e3_4, h4 = _triplet_for_arg(wrapped_args[4], dcptr, 4, sess, use_flow, aff_idx)
        e1_5, e2_5, e3_5, h5 = _triplet_for_arg(wrapped_args[5], dcptr, 5, sess, use_flow, aff_idx)
        e1_6, e2_6, e3_6, h6 = _triplet_for_arg(wrapped_args[6], dcptr, 6, sess, use_flow, aff_idx)
        e1_7, e2_7, e3_7, h7 = _triplet_for_arg(wrapped_args[7], dcptr, 7, sess, use_flow, aff_idx)
        h1p, h2p, h3p, h4p, h5p, h6p, h7p = _ph(h1), _ph(h2), _ph(h3), _ph(h4), _ph(h5), _ph(h6), _ph(h7)
        GC.@preserve id_ref h1p h2p h3p h4p h5p h6p h7p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                e1_2::Cint, e2_2::Ptr{Cvoid}, e3_2::Cint,
                e1_3::Cint, e2_3::Ptr{Cvoid}, e3_3::Cint,
                e1_4::Cint, e2_4::Ptr{Cvoid}, e3_4::Cint,
                e1_5::Cint, e2_5::Ptr{Cvoid}, e3_5::Cint,
                e1_6::Cint, e2_6::Ptr{Cvoid}, e3_6::Cint,
                e1_7::Cint, e2_7::Ptr{Cvoid}, e3_7::Cint,
                PEND::Cint
            )::Cvoid
        end
    else # n == 8
        e1_1, e2_1, e3_1, h1 = _triplet_for_arg(wrapped_args[1], dcptr, 1, sess, use_flow, aff_idx)
        e1_2, e2_2, e3_2, h2 = _triplet_for_arg(wrapped_args[2], dcptr, 2, sess, use_flow, aff_idx)
        e1_3, e2_3, e3_3, h3 = _triplet_for_arg(wrapped_args[3], dcptr, 3, sess, use_flow, aff_idx)
        e1_4, e2_4, e3_4, h4 = _triplet_for_arg(wrapped_args[4], dcptr, 4, sess, use_flow, aff_idx)
        e1_5, e2_5, e3_5, h5 = _triplet_for_arg(wrapped_args[5], dcptr, 5, sess, use_flow, aff_idx)
        e1_6, e2_6, e3_6, h6 = _triplet_for_arg(wrapped_args[6], dcptr, 6, sess, use_flow, aff_idx)
        e1_7, e2_7, e3_7, h7 = _triplet_for_arg(wrapped_args[7], dcptr, 7, sess, use_flow, aff_idx)
        e1_8, e2_8, e3_8, h8 = _triplet_for_arg(wrapped_args[8], dcptr, 8, sess, use_flow, aff_idx)
        h1p, h2p, h3p, h4p, h5p, h6p, h7p, h8p = _ph(h1), _ph(h2), _ph(h3), _ph(h4), _ph(h5), _ph(h6), _ph(h7), _ph(h8)
        GC.@preserve id_ref h1p h2p h3p h4p h5p h6p h7p h8p begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                e1_2::Cint, e2_2::Ptr{Cvoid}, e3_2::Cint,
                e1_3::Cint, e2_3::Ptr{Cvoid}, e3_3::Cint,
                e1_4::Cint, e2_4::Ptr{Cvoid}, e3_4::Cint,
                e1_5::Cint, e2_5::Ptr{Cvoid}, e3_5::Cint,
                e1_6::Cint, e2_6::Ptr{Cvoid}, e3_6::Cint,
                e1_7::Cint, e2_7::Ptr{Cvoid}, e3_7::Cint,
                e1_8::Cint, e2_8::Ptr{Cvoid}, e3_8::Cint,
                PEND::Cint
            )::Cvoid
        end
    end
    return nothing
end

# ═══════════════════════════════════════════════════════════════════════════════
# @spawn macro
#
#   PaRSEC.@spawn tp "task_name" f(INOUT(A), IN(B), VAL(i))
# ═══════════════════════════════════════════════════════════════════════════════

macro spawn(tp, name, call_expr)
    Meta.isexpr(call_expr, :call) ||
        error("@spawn expects f(args...), got: $(call_expr)")

    func = esc(call_expr.args[1])
    raw_args = call_expr.args[2:end]

    wrapped_syms   = [gensym("w$k") for k in 1:length(raw_args)]
    unwrapped_syms = [gensym("u$k") for k in 1:length(raw_args)]

    stmts = Expr[]

    for (ws, us, ra) in zip(wrapped_syms, unwrapped_syms, raw_args)
        push!(stmts, :( $ws = $(esc(ra)) ))
        push!(stmts, :( $us = $(_unwrap)($ws) ))
    end

    for ws in wrapped_syms
        push!(stmts, quote
            if !$(_is_val)($ws)
                lock(_pins_lock) do
                    push!(_active_pins, $(_unwrap)($ws))
                end
            end
        end)
    end

    id_sym = gensym("id")
    push!(stmts, :( $id_sym = $(_register_invocation)(
        $func, ($(unwrapped_syms...),)) ))
    push!(stmts, :( $(_do_insert_task)(
        $(esc(tp)), $(esc(name)), $id_sym,
        Any[$(wrapped_syms...)]) ))

    return Expr(:block, stmts...)
end

# ═══════════════════════════════════════════════════════════════════════════════
# taskpool scope
# ═══════════════════════════════════════════════════════════════════════════════

const _active_pins = Any[]
const _pins_lock   = ReentrantLock()

"""
    PaRSEC.taskpool(f, ctx)

Create a DTD taskpool, execute `f(tp)` to insert tasks via `@spawn`,
then wait for all tasks to complete and clean up.

```julia
PaRSEC.taskpool(ctx) do tp
    PaRSEC.@spawn tp "compute" my_func!(INOUT(A), IN(B), VAL(Cint(42)))
end
```
"""
function taskpool(f, ctx::Ptr{LibPaRSEC.parsec_context_s})
    tp = LibPaRSEC.parsec_dtd_taskpool_new()
    tp == C_NULL && error("parsec_dtd_taskpool_new failed")

    lock(_pins_lock) do; empty!(_active_pins); end

    LibPaRSEC.parsec_context_add_taskpool(ctx, tp)
    LibPaRSEC.parsec_context_start(ctx)

    _ensure_data_dist_init!()
    LibPaRSEC.parsec_data_init(ctx)

    myrank, nodes, mpi_multi = _mpi_rank_nodes_affinity()
    dc_buf = zeros(UInt8, sizeof(_DC))
    sess = _DtdArraySession(ctx, dc_buf, Dict{UInt64, Ptr{LibPaRSEC.parsec_data_t}}(),
                            Any[], myrank, nodes, mpi_multi)
    dcptr = _dtd_session_ptr(sess)
    LibPaRSEC.parsec_data_collection_init(dcptr, Cint(nodes), Cint(myrank))
    _install_julia_dc_vtable!(dcptr)
    LibPaRSEC.parsec_dtd_data_collection_init(dcptr)
    _dtd_array_session[] = sess

    try
        f(tp)
    finally
        LibPaRSEC.parsec_dtd_data_flush_all(tp, dcptr)
        LibPaRSEC.parsec_taskpool_wait(tp)
        for pdata in values(sess.data_by_key)
            LibPaRSEC.parsec_data_destroy(pdata)
        end
        empty!(sess.data_by_key)
        LibPaRSEC.parsec_dtd_data_collection_fini(dcptr)
        LibPaRSEC.parsec_data_collection_destroy(dcptr)
        _dtd_array_session[] = nothing
        LibPaRSEC.parsec_taskpool_free(tp)
        lock(_pins_lock) do; empty!(_active_pins); end
        lock(_invocation_lock) do; empty!(_invocation_table); end
    end
end