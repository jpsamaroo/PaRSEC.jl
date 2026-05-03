# ─────────────────────────────────────────────────────────────────────────────
# highlevel.jl — High-level DTD task spawning interface
#
# Included from src/PaRSEC.jl.  Provides:
#   PaRSEC.taskpool(f, ctx)
#   PaRSEC.@spawn tp "name" f(INOUT(A), IN(B), VAL(i))
#   PaRSEC.VAL, PaRSEC.IN, PaRSEC.OUT, PaRSEC.INOUT
# ─────────────────────────────────────────────────────────────────────────────

using Libdl: dlopen, dlsym

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
# All our tasks use PARSEC_VALUE-only args, so flow_count_of_tc is always 0.
# If every @spawn used the same @cfunction pointer, every arity would collide on
# one task class with the wrong count_of_params → heap corruption / segfault.
# Each arity therefore needs a distinct C entry point.
#
# parsec_dtd_unpack_args consumes exactly count_of_params variadic void* destinations
# (one per packed VALUE / flow).  A single @ccall must not pass extra unused variadic
# slots — the Julia variadic ABI only forwards the arguments we list.

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

# @cfunction pointers must be created at runtime (__init__), not baked into the
# pkgimage — otherwise Julia can record invalid / stale code pointers and PaRSEC
# jumps into garbage when executing tasks (segfault in __parsec_execute).
const _trampoline_cfn_by_nargs = Ref{NTuple{9,Ptr{Cvoid}}}(ntuple(_ -> Ptr{Cvoid}(0), 9))

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
    return nothing
end

# ═══════════════════════════════════════════════════════════════════════════════
# Triplet construction
#
# PaRSEC insert_task variadic triplets:
#   VALUE:  (sizeof(T),    &value,          PARSEC_VALUE)
#   REF:    (PASSED_BY_REF, data_of_key(…), direction)
#
# Until parsec_data_collection_t integration is done, REF args are packed
# as VALUE (pointer bits copied) — correct execution, no dependency tracking.
# ═══════════════════════════════════════════════════════════════════════════════

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

_make_triplet(wa::InArg)    = _make_ptr_value_triplet(_unwrap(wa))
_make_triplet(wa::OutArg)   = _make_ptr_value_triplet(_unwrap(wa))
_make_triplet(wa::InOutArg) = _make_ptr_value_triplet(_unwrap(wa))

# ═══════════════════════════════════════════════════════════════════════════════
# Task insertion — fixed-arity dispatchers
# ═══════════════════════════════════════════════════════════════════════════════

function _do_insert_task(tp::Ptr{LibPaRSEC.parsec_taskpool_t}, name::String,
                         invocation_id::UInt64, wrapped_args::Vector)
    n = length(wrapped_args)
    n > 8 && error("@spawn supports at most 8 arguments (got $n)")

    id_ref = Ref(invocation_id)
    itp = _hl_insert_task_ptr[]
    DEV = Cint(LibPaRSEC.PARSEC_DEV_CPU)
    PVAL = Cint(LibPaRSEC.PARSEC_VALUE)
    PEND = Cint(LibPaRSEC.PARSEC_DTD_ARG_END)
    id_sz = Cint(sizeof(UInt64))

    cfn = _trampoline_cfn_by_nargs[][n + 1]
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
        e1_1, e2_1, e3_1, h1 = _make_triplet(wrapped_args[1])
        GC.@preserve id_ref h1 begin
            @ccall $itp(
                tp::Ptr{LibPaRSEC.parsec_taskpool_t}, cfn::Ptr{Cvoid},
                Cint(0)::Cint, DEV::Cint, name::Cstring ;
                id_sz::Cint, id_ref::Ptr{UInt64}, PVAL::Cint,
                e1_1::Cint, e2_1::Ptr{Cvoid}, e3_1::Cint,
                PEND::Cint
            )::Cvoid
        end
    elseif n == 2
        e1_1, e2_1, e3_1, h1 = _make_triplet(wrapped_args[1])
        e1_2, e2_2, e3_2, h2 = _make_triplet(wrapped_args[2])
        GC.@preserve id_ref h1 h2 begin
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
        e1_1, e2_1, e3_1, h1 = _make_triplet(wrapped_args[1])
        e1_2, e2_2, e3_2, h2 = _make_triplet(wrapped_args[2])
        e1_3, e2_3, e3_3, h3 = _make_triplet(wrapped_args[3])
        GC.@preserve id_ref h1 h2 h3 begin
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
        e1_1, e2_1, e3_1, h1 = _make_triplet(wrapped_args[1])
        e1_2, e2_2, e3_2, h2 = _make_triplet(wrapped_args[2])
        e1_3, e2_3, e3_3, h3 = _make_triplet(wrapped_args[3])
        e1_4, e2_4, e3_4, h4 = _make_triplet(wrapped_args[4])
        GC.@preserve id_ref h1 h2 h3 h4 begin
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
    else
        error("5-8 args: extend _do_insert_task")
    end
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

    try
        f(tp)
    finally
        LibPaRSEC.parsec_taskpool_wait(tp)
        LibPaRSEC.parsec_taskpool_free(tp)
        lock(_pins_lock) do; empty!(_active_pins); end
        lock(_invocation_lock) do; empty!(_invocation_table); end
    end
end