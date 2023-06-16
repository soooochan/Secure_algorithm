#include <iostream>
#include <vector>
#include <gmpxx.h>

using namespace std;

struct Point
{
    mpz_class x;
    mpz_class y;
};
struct EC
{
    mpz_class a;
    mpz_class b;
    mpz_class p;
};
struct ECDSA_PK
{
    EC E;
    Point G;
    mpz_class n;
    Point Q;
};
struct ECDSA_SK
{
    EC E;
    Point G;
    mpz_class n;
    Point Q;
    mpz_class d;
};
struct ECDSA_SIG
{
    mpz_class S1;
    mpz_class S2;
};

// ECDSA_keygen, sign, verify
void ECDSA_keygen(ECDSA_PK *pk, ECDSA_SK *sk);                // 키생성
ECDSA_SIG ECDSA_sign(ECDSA_SK sk, mpz_class msg);             // 서명
bool ECDSA_verify(ECDSA_PK pk, ECDSA_SIG sig, mpz_class msg); // 검증

// mpz_class (urandomm, mod_inv, mod, cmp)

// mpz_class //
mpz_class urandomm(gmp_randstate_t state, const mpz_class p);
mpz_class mod_inv(mpz_class x, mpz_class mod);
mpz_class mod(mpz_class n, mpz_class p);
int cmp(mpz_class A, mpz_class B);

// EC_add, EC_double, EC_mult //
void EC_add(EC E, Point *R, Point P, Point Q);
void EC_double(EC E, Point *R, Point P);
void EC_mult(EC E, Point *R, Point P, mpz_class r);

void EC_add(EC E, Point *R, Point P, Point Q)
{
    mpz_class r;
    mpz_class p;
    mpz_class xtemp, ytemp;
    mpz_class Rx, Ry;
    if (P.x == 0 && P.y == 0)
        *R = Q;
    else if (Q.x == 0 && Q.y == 0)
        *R = P;
    else if (P.x == Q.x && P.y == Q.y)
        EC_double(E, R, P);
    else
    {
        p = E.p;
        xtemp = Q.x - P.x;
        xtemp = mod(xtemp, E.p);
        xtemp = mod_inv(xtemp, E.p);
        if (xtemp == 0)
        { // infinity
            R->x = 0;
            R->y = 0;
        }
        else if (r < 0)
        {
            cout << "error" << endl;
        }
        else
        {
            ytemp = Q.y - P.y;
            ytemp = mod(ytemp, E.p);
            r = xtemp * ytemp;
            r = mod(r, E.p);
            Rx = mod((r * r - P.x - Q.x), E.p);
            R->x = Rx;
            Ry = mod(r * (P.x - Rx) - P.y, E.p);
            R->y = Ry;
        }
    }
}

void EC_double(EC E, Point *R, Point P)
{
    mpz_class r;
    mpz_class xtemp, ytemp;
    mpz_class Rx, Ry;

    ytemp = 2 * P.y;
    ytemp = mod(ytemp, E.p);
    ytemp = mod_inv(ytemp, E.p);

    xtemp = (3 * P.x * P.x) + E.a;
    xtemp = mod(xtemp, E.p);

    r = xtemp * ytemp;
    r = mod(r, E.p);

    Rx = r * r - (2 * P.x);
    Rx = mod(Rx, E.p);
    R->x = Rx;

    Ry = r * (P.x - Rx) - P.y;
    Ry = mod(Ry, E.p);
    R->y = Ry;
}

void EC_double(EC E, Point *R, Point P)
{
    mpz_class r;
    mpz_class xtemp, ytemp;
    mpz_class Rx, Ry;

    ytemp = 2 * P.y;
    ytemp = mod(ytemp, E.p);
    ytemp = mod_inv(ytemp, E.p);

    xtemp = (3 * P.x * P.x) + E.a;
    xtemp = mod(xtemp, E.p);

    r = xtemp * ytemp;
    r = mod(r, E.p);

    Rx = r * r - (2 * P.x);
    Rx = mod(Rx, E.p);
    R->x = Rx;

    Ry = r * (P.x - Rx) - P.y;
    Ry = mod(Ry, E.p);
    R->y = Ry;
}

int main()
{
    struct ECDSA_PK pk;
    struct ECDSA_SK sk;
    struct ECDSA_SIG sig;

    mpz_class msg{"0x19"};
    bool rop;

    ECDSA_keygen(&pk, &sk);
    sig = ECDSA_sign(sk, msg);
    rop = ECDSA_verify(pk, sig, msg);

    if (rop == true)
        cout << "true" << endl;
    else if (rop == false)
        cout << "false" << endl;
    else
        cout << "error" << endl;
    return 0;
}

void ECDSA_keygen(ECDSA_PK *pk, ECDSA_SK *sk)
{
    // 랜덤 값 생성 //
    unsigned long seed;
    gmp_randstate_t state; // gmp_randstate_t 라는 자료형을 가지는 변수 선언
    random_device rd;
    // seed = time(NULL); (프로그램=을 실행했던 초를 시드 값  -> 시드 값이 너무 천ㅊ너히 변한다. )
    // seed = time(NULL) 은 0부터 99까지 균등하게 난수를 생성하지 않는다.
    seed = rd(); // 매번 실행될때 마다 다른 값이 생성되도록 구현
    // seed 값이 균등 분포
    gmp_randinit_mt(state); // gmp_randinit_mt 함수를 이용하여 해당 변수 초기화
    gmp_randseed_ui(state, seed);
    /////
    pk->E = {2, 2, 17};
    sk->E = pk->E;
    pk->G = {5, 1};
    sk->G = pk->G;
    pk->n = 19;
    sk->n = pk->n;

    // 개인키 1 ~ n-1 사이의 값 생성
    sk->d = urandomm(state, sk->n);
    EC_mult(sk->E, &sk->Q, sk->G, sk->d);

    pk->Q = sk->Q;
}

// 입력된 메시지 msg에 대한 서명을 생성하여 return
ECDSA_SIG ECDSA_sign(ECDSA_SK sk, mpz_class msg)

{
    unsigned long seed;
    random_device rd;
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    mpz_class k, inv_k;
    mpz_class h_m;
    Point R;
    ECDSA_SIG sig;
    do
    {
        // seed = time(NULL);
        seed = rd();
        gmp_randseed_ui(state, seed);
        k = urandomm(state, sk.n); // 1~n 사이의 값
        EC_mult(sk.E, &R, sk.G, k);
    } while (mod(R.x, sk.n) == 0); // (x1 mod n =0 이면 go back을 한다. )

    sig.S1 = mod(R.x, sk.n);

    int nBit;
    int mBit;

    nBit = mpz_sizeinbase(sk.n.get_mpz_t(), 2); // 최상위 nbit만 추출하여 사용
    mBit = mpz_sizeinbase(msg.get_mpz_t(), 2);  // 메세지 비트
    h_m = msg >> max(mBit - nBit, 0);
    // h(m) : 입력된 msg의 최상위 nBit ( 차수 n의 비트 수)만 추출하여 사용 ( 임시방편 )

    inv_k = mod_inv(k, sk.n);
    if (inv_k == 0)
    {
        cout << " inv_k doesn't exist";
        ECDSA_sign(sk, msg);
    }

    sig.S2 = h_m + (sig.S1 * sk.d);
    sig.S2 = mod(sig.S2, sk.n);
    sig.S2 = inv_k * sig.S2;
    sig.S2 = mod(sig.S2, sk.n);

    if (mod(sig.S2, sk.n) == 0 || mod_inv(sig.S2, sk.n) == 0)
    {
        cout << "repeat SIGN " << endl;
        return ECDSA_sign(sk, msg);
    }
    else
    {
        return sig;
    }
};

// 서명 검증
bool ECDSA_verify(ECDSA_PK pk, ECDSA_SIG sig, mpz_class msg)
{
    Point R;
    Point R1;
    Point R2;
    // Point R1;
    // Point R2;
    mpz_class u1;
    mpz_class u2;
    // Point u1;
    // Point u2;
    mpz_class S2_inv;
    mpz_class h_m;
    int nBit, mBit;

    nBit = mpz_sizeinbase(pk.n.get_mpz_t(), 2); // 최상위 nbit만 추출하여 사용
    mBit = mpz_sizeinbase(msg.get_mpz_t(), 2);  // 메세지 비트
    h_m = msg >> max(mBit - nBit, 0);

    S2_inv = mod_inv(sig.S2, pk.n);
    S2_inv = mod(S2_inv, pk.n);
    u1 = mod(h_m * S2_inv, pk.n);
    u2 = mod(sig.S1 * S2_inv, pk.n);
    // u2.x = mod(sig.S1 * S2_inv, pk.n);
    // u1.x = mod(h_m * S2_inv, pk.n);
    // u2.x = mod(sig.S1 * S2_inv, pk.n);
    // cout << u1.x << endl;
    // cout << u2.x << endl;
    EC_mult(pk.E, &R1, pk.G, u1);
    EC_mult(pk.E, &R2, pk.Q, u2);

    EC_add(pk.E, &R, R1, R2);

    // EC_mult(pk.E, &u1, pk.G, u1.x);
    // EC_mult(pk.E, &u2, pk.Q, u2.x);
    // EC_add(pk.E, &R, u1, u2);

    if (R.x == 0 && R.y == 0)
    {
        cout << "Poing of infinity" << endl;
        return false;
    }
    else

    {

        cout << sig.S1 << endl;
        cout << mod(R.x, pk.n) << endl;
        if (cmp(sig.S1, mod(R.x, pk.n)) == 0)
            return true;
        else
            return false;
    }
};
