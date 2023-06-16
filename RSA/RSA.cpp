
#include <iostream>
#include <vector>
#include <gmpxx.h>

using namespace std;

void RSA_keygen(RSA *pk, RSA_SK *sk, int key_size);
mpz_class RSA_encrypt(RSA_PK pk, mpz_class msg);
mpz_clss RSA_decrypt(RSA_SK sk, mpz_class ct);
mpz_class RSA_sign(RSA_SK sk, mpz_class msg);
bool RSA_verify(RSA_PK pk, mpz_class sig, mpz_class msg);

void RSA_keygen(RSA *pk, RSA_SK *sk, int key_size);
mpz_class RSA_encrypt(RSA_PK pk, mpz_class msg);
mpz_clss RSA_decrypt(RSA_SK sk, mpz_class ct);
mpz_class RSA_sign(RSA_SK sk, mpz_class msg);
bool RSA_verify(RSA_PK pk, mpz_class sig, mpz_class msg);

void RSA_keygen(RSA *pk, RSA_SK *sk, int key_size);
mpz_class RSA_encrypt(RSA_PK pk, mpz_class msg);
mpz_clss RSA_decrypt(RSA_SK sk, mpz_class ct);
mpz_class RSA_sign(RSA_SK sk, mpz_class msg);
bool RSA_verify(RSA_PK pk, mpz_class sig, mpz_class msg);

struct RSA_PK
{
    mpz_class e;
    mpz_class N;
}

struct RSA_DK
{
    mpz_class e;
    mpz_class d;
    mpz_class p;
    mpz_class q;
    mpz_class N;
}

int
main()
{
    mpz_class msg, ct, dt, sig;
    RSA_PK pk;
    RSA_SK sk;

    msg = {"0x185351235"};

    RSA_keygen(pk, sk, 2048);

    ct = RSA_encrypt(pk, msg);
    // dt = RSA_decrypt(sk, ct);
    dt = RSA_decrypt_crt(sk, ct);

    if (cmp(msg, dt) == 0)
        cout << "success" << endl;
    else
        cout << "fail" << endl;

    sig = RSA_sign(sk, msg);
    if (RSA_verify(pk, sig, msg))
        cout << "success" << endl;
    else
        cout << "fail" << endl;

    // complie -> gcc RSA.cpp -lstdc++ -lgmpxx -lgmp -o RSA
    return 0;
}

mpz_class mod(mpz_class n, mpz_class p)
{
    mpz_class result;
    mpz_mod(result.get_mpz_t(), n.get_mpz_t(), p.get_mpz_t());
    return result;
}
mpz_class urandomb(gmp_randstate_t state, unsigned int bit)
{
    mpz_class result;
    mpz_rrandomb(result.get_mpz_t(), state, bit);
    return result;
}
mpz_class nextprime(mpz_class n)
{
    mpz_class result;
    mpz_nextprime(result.get_mpz_t(), n.get_mpz_t());
    return result;
}
mpz_class random_prime(unsigned int bit)
{
    mpz_class num;
    unsigned long seed;
    gmp_randstate_t state;

    mpz_class prime;
    do
    {
        seed = time(NULL);
        gmp_randinit_mt(state);
        gmp_randseed_ui(state, seed);

        num = urandomb(state, bit);

        prime = nextprime(num);
    } while (mpz_sizeinbase(prime.get_mpz_t(), 2) != bit);

    return prime;
}
mpz_class lcm(mpz_class a, mpz_class b)
{
    mpz_class result;
    mpz_lcm(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return result;
}
mpz_class gcd(mpz_class a, mpz_class b)
{
    mpz_class result;
    mpz_gcd(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return result;
}
mpz_class mod_inv(mpz_class x, mpz_class mod)
{
    mpz_class result;
    if (mpz_invert(result.get_mpz_t(), x.get_mpz_t(), mod.get_mpz_t()) == 0)
        cout << "error. result will be empty" << endl;
    return result;
}
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod)
{
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}
int cmp(mpz_class x, mpz_class y)
{
    return mpz_cmp(x.get_mpz_t(), y.get_mpz_t());
}

void RSA_keygen(RSA_PK &pk, RSA_SK &sk, int key_size)
{

    sk.p = random_prime(key_size / 2);
    sk.q = random_prime(key_size / 2);
    while (cmp(sk.p, sk.q) == 0)
        sk.q = random_prime(key_size / 2);

    sk.N = sk.p * sk.q;
    pk.N = sk.N;

    mpz_class ell = lcm(sk.p - 1, sk.q - 1);
    pk.e = 0x10001;

    if (gcd(pk.e, ell) != 1)
        pk.e = nextprime(pk.e);

    sk.e = pk.e;
    sk.d = mod_inv(pk.e, ell);
}
mpz_class RSA_encrypt(RSA_PK pk, mpz_class msg)
{
    return powm(msg, pk.e, pk.N);
}
mpz_class RSA_decrypt(RSA_SK sk, mpz_class ct)
{
    return powm(ct, sk.d, sk.N);
}
mpz_class RSA_decrypt_crt(RSA_SK sk, mpz_class ct)
{
    mpz_class m_1, m_2, temp1, temp2;

    m_1 = powm(ct, sk.d, sk.p);
    m_2 = powm(ct, sk.d, sk.q);

    temp1 = m_1 * sk.q * mod_inv(sk.q, sk.p);
    temp2 = m_2 * sk.p * mod_inv(sk.p, sk.q);

    return mod(temp1 + temp2, sk.N);
}
mpz_class RSA_sign(RSA_SK sk, mpz_class msg)
{
    return powm(msg, sk.d, sk.N);
}
bool RSA_verify(RSA_PK pk, mpz_class sig, mpz_class msg)
{
    mpz_class dt = powm(sig, pk.e, pk.N);
    if (cmp(dt, msg) == 0)
        return true;
    else
        return false;
}