struct pkcs1_v2_2 end
function pad(::pkcs1_v2_2,
             msg::Union{AbstractString,AbstractVector},
             key::RSAPublicKey;
             label="")
    k = 1 # length of cypher text
    lHash = SHA.sha1(label)
    hLen = lHash |> length
    LLen = label |> length
    LLen > (big"2" << (60*8)) && throw(error("label too long"))
    mLen = msg |> length 
    mLen > k - 2 * hLen - 2 && throw(error("message too long"))
    pLen = k - mLen - 2 * hLen -2
    PS = Vector{UInt8}(0, pLen)
    DB = vcat(lHash, PS, Vector{UInt8}(1, 1), msg)
    seed = rand{UInt8}(hLen)
    dbMask = MGF(seed, k - hLen - 1)
    maskedDB = DB .⊻ dbMask
    seedMask = MGF(maskedDB, hLen)
    maskedSeed = seed .⊻ seedMask
    EM = hcat(Vector{UInt8}(0, 1), maskedSeed, maskedDB)
end

function MGF1(mgfSeed::Vector{UInt8}, maskLen:: Integer; hash = SHA.sha1)
    hLen = hash("") |> length
    maskLen >= (2 << 32) && error("mask too long") |> throw
    T = Vector{UInt8}()
    for counter in big"0":BigInt((ceil(maskLen / hLen) - 1))
        C = I2OSP(counter, 4) |> Vector{UInt8}
        T = vcat(T, hash(vcat(mgfSeed, C) |> String))
    end
    return T[1:maskLen]
end
