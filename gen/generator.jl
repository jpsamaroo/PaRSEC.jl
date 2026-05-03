using Clang
using Clang.Generators
using PaRSEC
using PaRSEC.PaRSEC_jll
using MPI
using Hwloc_jll

cd(@__DIR__)

include_dir = normpath(PaRSEC_jll.artifact_dir, "include")
parsec_dir = joinpath(include_dir, "parsec")

# MPI include dir (derived from MPI library path)
mpi_include_dir = joinpath(dirname(dirname(MPI.API.libmpi)), "include")

# Hwloc include dir
hwloc_include_dir = joinpath(Hwloc_jll.artifact_dir, "include")

options = load_options(joinpath(@__DIR__, "generator.toml"))

# add compiler flags, e.g. "-DXXXXXXXXX"
args = get_default_args()  # Note you must call this function firstly and then append your own flags
push!(args, "-I$include_dir")
push!(args, "-I$mpi_include_dir")
push!(args, "-I$hwloc_include_dir")

# Map __int128_t to Julia's Int128 so struct fields and function params translate correctly
Clang.Generators.add_definition(:__int128_t => Clang.Generators.JuliaCint128())

#headers = [joinpath(parsec_dir, header) for header in readdir(parsec_dir) if endswith(header, ".h")]
# there is also an experimental `detect_headers` function for auto-detecting top-level headers in the directory
headers = detect_headers(parsec_dir, args)

# create context
ctx = create_context(headers, args, options)

# Run passes in stages with manual DAG fixups in between.

# Stage 1: Run all passes up to (but not including) Codegen.
codegen_idx = findfirst(p -> p isa Codegen, ctx.passes)
for pass in ctx.passes[1:codegen_idx-1]
    pass(ctx.dag, ctx.options)
end

# Fixup 1: Replace StructMutualRef nodes that contain flexible array members with opaque
# structs. parsec_data_s has a `device_copies[]` field (flexible array member of pointers)
# which Clang.jl's StructMutualRef codegen doesn't support.
for (i, node) in enumerate(ctx.dag.nodes)
    if node.type isa Clang.Generators.StructMutualRef
        cursor = node.cursor
        has_flex_array = any(Clang.fields(Clang.getCursorType(cursor))) do field
            ty = Clang.getCursorType(field)
            ty isa Clang.CLIncompleteArray
        end
        if has_flex_array
            ctx.dag.nodes[i] = Clang.Generators.ExprNode(
                node.id, Clang.Generators.StructOpaqueDecl(),
                node.cursor, node.exprs, node.adj)
        end
    end
end

# Stage 2: Run Codegen and passes up to (but not including) CodegenMacro.
macro_codegen_idx = findfirst(p -> p isa CodegenMacro, ctx.passes)
for pass in ctx.passes[codegen_idx:macro_codegen_idx-1]
    pass(ctx.dag, ctx.options)
end

# Fixup 2: Mark macro nodes whose bodies contain C-only tokens (restrict, ->) as
# MacroUnsupported so they are skipped rather than emitting invalid Julia code.
for (i, node) in enumerate(ctx.dag.nodes)
    node.type isa Clang.Generators.MacroDefault || continue
    toks = collect(Clang.tokenize(node.cursor))
    # C datatype keywords that signal a type-cast expression in macro bodies
    c_type_keywords = Set(["char", "double", "float", "int", "long", "short",
                           "signed", "unsigned", "void", "_Bool", "_Complex"])
    # C stdint/size typedef names defined in prologue.jl as Julia type aliases
    c_typedef_names = Set(["uint8_t", "uint16_t", "uint32_t", "uint64_t",
                           "int8_t", "int16_t", "int32_t", "int64_t",
                           "uintptr_t", "intptr_t", "size_t", "ssize_t",
                           "ptrdiff_t"])
    is_bad = any(toks[2:end]) do tok
        # C-only pointer dereference operator
        Clang.Generators.is_punctuation(tok) && tok.text == "->" ||
        # restrict keyword (not valid in Julia)
        (Clang.Generators.is_keyword(tok) || Clang.Generators.is_identifier(tok)) &&
            tok.text == "restrict" ||
        # Hex literals >= 0x80000000 overflow Int32 (used in MPI handle values)
        Clang.Generators.is_literal(tok) && startswith(tok.text, "0x") &&
            tryparse(UInt32, tok.text) !== nothing &&
            tryparse(UInt32, tok.text) > typemax(Int32) ||
        # C type keywords in macro body typically indicate C-style type casts
        Clang.Generators.is_keyword(tok) && tok.text ∈ c_type_keywords ||
        # NULL is a C macro not available in Julia (use C_NULL instead)
        Clang.Generators.is_identifier(tok) && tok.text == "NULL" ||
        # offsetof is a C macro / compiler builtin with no Julia equivalent
        Clang.Generators.is_identifier(tok) && tok.text == "offsetof" ||
        # C compound initializers {a, b, c} are not valid Julia syntax
        Clang.Generators.is_punctuation(tok) && tok.text == "{" ||
        # C logical operators || and && require booleans in Julia but are used
        # with integer operands in C (which returns int, not bool)
        Clang.Generators.is_punctuation(tok) && (tok.text == "||" || tok.text == "&&") ||
        # Identifiers ending in _ are C token-pasting prefixes (e.g., hwloc_, HWLOC_)
        # which have no Julia equivalent and would cause UndefVarError
        Clang.Generators.is_identifier(tok) && endswith(tok.text, "_")
    end
    # Additional check: C typedef name used in arithmetic context (cast like (uint32_t)-1).
    # Pattern: `type )` followed by anything other than `(` means it's a C cast in arithmetic,
    # not a constructor call. E.g., `(uint32_t)-1` → tokens: `uint32_t )`  `-`  `1`  (bad)
    #            `(uint8_t)(expr)` → tokens: `uint8_t`  `)`  `(`  ...   (ok → `uint8_t(expr)`)
    if !is_bad
        for j in 2:length(toks)-1
            tok = toks[j]
            if Clang.Generators.is_identifier(tok) && tok.text ∈ c_typedef_names
                # Find the next non-paren token after the type name
                k = j + 1
                # Skip a single closing paren (the `(type)` cast syntax)
                if k <= length(toks) && Clang.Generators.is_punctuation(toks[k]) && toks[k].text == ")"
                    k += 1
                end
                # If the next token (after optional `)`) is not `(`, it's arithmetic cast
                if k > length(toks) || !(Clang.Generators.is_punctuation(toks[k]) && toks[k].text == "(")
                    is_bad = true
                    break
                end
            end
        end
    end
    if is_bad
        ctx.dag.nodes[i] = Clang.Generators.ExprNode(
            node.id, Clang.Generators.MacroUnsupported(),
            node.cursor, node.exprs, node.adj)
    end
end

# Stage 3: Run the remaining passes (CodegenMacro and printers).
for pass in ctx.passes[macro_codegen_idx:end]
    pass(ctx.dag, ctx.options)
end

# Post-process: fix signed 32-bit overflow in type-constructor bit-shift expressions.
# C: `(parsec_dependency_t)(1 << 31)` is valid (wraps to INT32_MIN), but in Julia
# `Int32(1 << 31)` throws InexactError because 1<<31 is Int64(2147483648).
# Rewrite as `reinterpret(Int32, UInt32(value))` to preserve the intended bit pattern.
let output_path = normpath(@__DIR__, options["general"]["output_file_path"])
    content = read(output_path, String)
    content = replace(content,
        r"parsec_dependency_t\((\d+) << (\d+)\)" => function(m)
            m2 = match(r"parsec_dependency_t\((\d+) << (\d+)\)", m)
            val = parse(UInt32, m2[1]) << parse(Int, m2[2])
            "reinterpret(Int32, UInt32(0x$(string(val, base=16))))"
        end)
    # Julia only recognises 0x (lowercase) hex prefix; C also allows 0X (uppercase).
    content = replace(content, r"0X([0-9A-Fa-f]+)" => s"0x\1")
    write(output_path, content)
end

@info "Done!"
