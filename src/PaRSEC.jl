module PaRSEC

import PaRSEC_jll

include("LibPaRSEC.jl")
include("highlevel.jl")

function __init__()
    _hl_init()
    _init_dtd_dc_callbacks!()
    _init_trampoline_cfunctions!()
end

end # module PaRSEC
