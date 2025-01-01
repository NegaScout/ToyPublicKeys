import Random

@testset "pass_trough_GMP" begin
    function pass_trough_GMP(str::String)
        bi = BigInt()
        _order = 0
        _endian = 0
        _nails = 0
        # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
        # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
        msg_ = codeunits(str)
        Base.GMP.MPZ.import!(
            bi, length(msg_), _order, sizeof(eltype(msg_)), _endian, _nails, pointer(msg_)
        )
        # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
        # void * mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
        buff = Vector{UInt8}(undef, bi.size)
        Base.GMP.MPZ.export!(buff, bi; order=_order, nails=_nails, endian=_endian)
        return String(buff)
    end
    test_str = "this_is_test_str"
    @test ToyPublicKeys.pass_trough_GMP(test_str) == "this_is_test_str"
end

@testset "power_crt" begin
    base = big"123456"
    modul = big"265277633"
    f1 = big"38561"
    f2 = big"15107"
    pow_crt = ToyPublicKeys.power_crt(base, modul, f1, f2)
    pow_m = Base.GMP.MPZ.powm(base, modul, f1*f2)
    @test pow_crt == pow_m
end

@testset "RSAStep(RSAStep) is identity ~ BigInt" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_RSAKeyPair(2048)
    msg = big"2"
    encrypted = ToyPublicKeys.RSAStep(msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(encrypted, private_key)
    @test msg == decrypted
end

@testset "RSAStep(RSAStep) is identity ~ CodeUnits" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_RSAKeyPair(2048)
    msg = codeunits("2")
    encrypted = ToyPublicKeys.RSAStep(msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(encrypted, private_key)
    @test msg == decrypted
end

@testset "RSAStep(RSAStep) is identity ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_RSAKeyPair(2048)
    msg = "2"
    encrypted = ToyPublicKeys.RSAStep(msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(encrypted, private_key)
    @test msg == decrypted
end

@testset "padding/pkcs_1_v1_5" begin
    test_vector = Vector{UInt8}([1,2,3])
    Random.seed!(42)
    padded_vector_correct = UInt8[0x00, 0x02, 0x7a, 0xb4, 0xac, 0x2b, 0x9d, 0xab, 0x75, 0x4d, 0xa9, 0xa4, 0x58, 0x45, 0x84, 0x17, 0x46, 0x31, 0x6d, 0x7c, 0x15, 0x84, 0x33, 0x9a, 0x66, 0x51, 0x6f, 0xdb, 0x52, 0x90, 0x53, 0x29, 0xb9, 0x5f, 0x00, 0x01, 0x02, 0x03]
    padded_vec = ToyPublicKeys.pad(test_vector)
    @test padded_vector_correct == padded_vec
    unpadded_vector = ToyPublicKeys.unpad(padded_vector_correct)
    @test test_vector == unpadded_vector
    @test UInt8[0x00, 0x02, 0x00, 0x01, 0x02, 0x03] == ToyPublicKeys.pad(test_vector, 0)
end

@testset "Decryption(Encryption) is identity ~ CodeUnits" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_RSAKeyPair(2048)
    msg = Base.CodeUnits("1")
    encrypted = ToyPublicKeys.encrypt(msg, public_key; pad_length = 1)
    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    @test decrypted == msg
end

@testset "Decryption(Encryption) is identity ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_RSAKeyPair(2048)
    msg = "1"
    encrypted = ToyPublicKeys.encrypt(msg, public_key; pad_length = 1)
    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    @test decrypted == msg
end

@testset "verify_signature(sign) is true ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_RSAKeyPair(2048)
    msg = "1"
    signature = ToyPublicKeys.sign(msg, private_key; pad_length = 1)
    @test ToyPublicKeys.verify_signature(msg, signature, public_key)
end