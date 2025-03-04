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
    @test pass_trough_GMP(test_str) == "this_is_test_str"
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

@testset "validate generate_rsa_key_pair" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    @test try
        ToyPublicKeys.validate(private_key)
        true
    catch
        false
    end
end

@testset "RSAStep(RSAStep) is identity ~ BigInt" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = big"2"
    encrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test msg == decrypted
end

@testset "RSAStep(RSAStep) is identity ~ CodeUnits" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = codeunits("2")
    encrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test msg == decrypted
end

@testset "RSAStep(RSAStep) is identity ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = "2"
    encrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test msg == decrypted
end

@testset "Decryption(Encryption) is identity ~ CodeUnits" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = Base.CodeUnits("1")
    encrypted = ToyPublicKeys.encrypt(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.decrypt(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test decrypted == msg
end

@testset "Decryption(Encryption) is identity ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = "1"
    encrypted = ToyPublicKeys.encrypt(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.decrypt(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test decrypted == msg
end

@testset "verify_signature(sign) is true ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = "1"
    signature = ToyPublicKeys.sign(ToyPublicKeys.pkcs1_v1_5, msg, private_key)
    @test ToyPublicKeys.verify_signature(ToyPublicKeys.pkcs1_v1_5, msg, signature, public_key)
end
