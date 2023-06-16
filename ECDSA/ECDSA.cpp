

1

    자료 2

    3

    A 4

    I 5

    Cyber_LAB 검색

        Cyber_LAB

            김지윤

                김지윤
    : 생쥐 : 2 : 21
#include <iostream>
#include <random>
#include <gmpxx.h>
#include <vector>
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
//----- 목표 알고리즘 : 키 생성, 서명, 검증
void ECDSA_keygen(ECDSA_PK *pk, ECDSA_SK *sk);
ECDSA_SIG ECDSA_sign(ECDSA_SK sk, mpz_class msg);
bool ECDSA_verify(ECDSA_PK pk, ECDSA_SIG sig, mpz_class msg);
//----- 래퍼 함수
mpz_class urandomm(gmp_randstate_t state, const mpz_class n);
mpz_class mod(mpz_class n, mpz_class p);
mpz_class mod_inv(mpz_class x, mpz_class mod);
int cmp(mpz_class x, mpz_class y);
//----- EC 연산 함수
void EC_add(EC E, Point *R, Point P, Point Q);
void EC_double(EC E, Point *R, Point P);
void EC_mult(EC E, Point *R, Point P, mpz_class r);
void bits_inv(vector<bool> *bits, mpz_class r);
int main()
{
    //-------------10/24
    Point A, B;
    Point R;
    EC E;
    A.x = 5;
    A.y = 1;
    B.x = 6;
    B.y = 3;
    E.a = 2;
    E.b = 2;
    E.p = 17;
    EC_mult(E, &R, A, 21);
    cout << "A : " << A.x << ", " << A.y << endl;
    cout << "R : " << R.x << ", " << R.y << endl;
    struct ECDSA_PK pk;
    struct ECDSA_SK sk;
    struct ECDSA_SIG sig;
    mpz_class msg{"0x10"};
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
//----- 목표 알고리즘 : 키 생성, 서명, 검증
void ECDSA_keygen(ECDSA_PK *pk, ECDSA_SK *sk)
{
    unsigned long seed;
    random_device rd;
    gmp_randstate_t state;
    pk->E = {2, 2, 17};
    sk->E = pk->E;
    pk->G = {5, 1};
    sk->G = pk->G;
    pk->n = 19;
    sk->n = pk->n;
    seed = rd(); // seed = time(NULL);
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    // 0이 뽑히는 예외, sk->n보다 작은 예외 처리 필요할 것
    sk->d = urandomm(state, sk->n);
    EC_mult(sk->E, &sk->Q, sk->G, sk->d);
    pk->Q = sk->Q;
}
ECDSA_SIG ECDSA_sign(ECDSA_SK sk, mpz_class msg)
{
    unsigned long seed;
    random_device rd;
    gmp_randstate_t state;
    mpz_class k, inv_k;
    mpz_class h_m;
    int nBit, mBit;
    Point R;
    ECDSA_SIG sig;
    // 임시 해시값 생성하기(너무 작아서 함수 이용 불가 )
    nBit = mpz_sizeinbase(sk.n.get_mpz_t(), 2);
    mBit = mpz_sizeinbase(msg.get_mpz_t(), 2);
    h_m = msg >> max(mBit - nBit, 0);
    // S1 구하기
    gmp_randinit_mt(state);
    do
    {
        seed = rd(); // seed = time(NULL);
        gmp_randseed_ui(state, seed);
        k = urandomm(state, sk.n);
        EC_mult(sk.E, &R, sk.G, k);
        sig.S1 = mod(R.x, sk.n);
    } while (sig.S1 == 0);
    // S2 구하기
    inv_k = mod_inv(k, sk.n);
    if (inv_k == 0)
    {
        cout << "inv_k doesn't exits" << endl;
        return ECDSA_sign(sk, msg);
    }
    sig.S2 = h_m + (sig.S1 * sk.d);
    sig.S2 = mod(sig.S2, sk.n);
    sig.S2 = inv_k * sig.S2;
    sig.S2 = mod(sig.S2, sk.n);
    if (mod(sig.S2, sk.n) == 0 || mod_inv(sig.S2, sk.n) == 0)
    {
        cout << "repeat SIGN" << endl;
        return ECDSA_sign(sk, msg);
    }
    else
        return sig;
}
bool ECDSA_verify(ECDSA_PK pk, ECDSA_SIG sig, mpz_class msg)
{
    mpz_class c;
    Point R;
    Point u1, u2;
    c = mod(mod_inv(sig.S2, pk.n), pk.n);
    //----------u1 계산
    int nBit, mBit;
    mpz_class h_m;
    nBit = mpz_sizeinbase(pk.n.get_mpz_t(), 2);
    mBit = mpz_sizeinbase(msg.get_mpz_t(), 2);
    h_m = msg >> max(mBit - nBit, 0);
    u1.x = mod((h_m * c), pk.n);
    //---------- u2 계산
    u2.x = mod((sig.S1 * c), pk.n);
    //---------- R 계산
    EC_mult(pk.E, &u1, pk.G, u1.x);
    EC_mult(pk.E, &u2, pk.Q, u2.x);
    EC_add(pk.E, &R, u1, u2);
    if (R.x == 0 && R.y == 0)
    {
        cout << "Point of infinity" << endl;
        return false;
    }
    else
    {
        if (cmp(sig.S1, mod(R.x, pk.n)) == 0)
            return true;
        else
            return false;
    }
}
//----- 래퍼함수
mpz_class urandomm(gmp_randstate_t state, const mpz_class n)
{
    mpz_class r;
    mpz_urandomm(r.get_mpz_t(), state, n.get_mpz_t());
    return r;
}
mpz_class mod(mpz_class n, mpz_class p)
{
    mpz_class r;
    mpz_mod(r.get_mpz_t(), n.get_mpz_t(), p.get_mpz_t()); // r = n mod p
    return r;
}
mpz_class mod_inv(mpz_class x, mpz_class mod)
{
    mpz_class r;
    if (mpz_invert(r.get_mpz_t(), x.get_mpz_t(), mod.get_mpz_t()) == 0)
        cout << "error: an inverse doesn't exist" << endl;
    return r;
}
int cmp(mpz_class x, mpz_class y)
{
    int r;
    r = mpz_cmp(x.get_mpz_t(), y.get_mpz_t());
    return r;
}
//----- EC 연산 함수
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
    if (ytemp == 0)
    {
        R->x = 0;
        R->y = 0;
    }
    else if (r < 0)
    {
        cout << "error" << endl;
    }
    else
    {
        xtemp = (3 * P.x * P.x) + E.a;
        xtemp = mod(xtemp, E.p);
        r = xtemp * ytemp;
        r = mod(r, E.p);
        Rx = mod((r * r - (2 * P.x)), E.p);
        R->x = Rx;
        Ry = mod((r * (P.x - Rx) - P.y), E.p);
        R->y = Ry;
    }
}
void EC_mult(EC E, Point *R, Point P, mpz_class r)
{
    vector<bool> bits;
    int n;
    bits_inv(&bits, r); // r > 0
    n = bits.size();
    *R = P; // R->x = P.x; P->y = P.y;
    for (; n > 1; n--)
    {
        EC_double(E, R, *R);
        if (bits.at(n - 2) == 1)
            EC_add(E, R, *R, P);
    }
}
void bits_inv(vector<bool> *bits, mpz_class r)
{
    for (; r > 0; r /= 2)
    {
        (*bits).push_back(r % 2 == 1);
    }
}

곽수찬
오후 7 : 16
#include <gmpxx.h>
    using namespace std;
#include <iostream>
#include <vector>
#include <random>
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
void ECDSA_keygen(ECDSA_PK *pk, ECDSA_SK *sk); // 키생성
ECDSA_SIG ECDSA_sign(ECDSA_SK sk, mpz_class msg);
bool ECDSA_verify(ECDSA_PK pk, ECDSA_SIG sig, mpz_class msg);
// mpz_class //
mpz_class urandomm(gmp_randstate_t state, const mpz_class p);
mpz_class mod_inv(mpz_class x, mpz_class mod);
mpz_class mod(mpz_class n, mpz_class p);
int cmp(mpz_class A, mpz_class B);
// EC_add, EC_double, EC_mult //
void EC_add(EC E, Point *R, Point P, Point Q);
void EC_double(EC E, Point *R, Point P);
void EC_mult(EC E, Point *R, Point P, mpz_class r);
void bits_inv(vector<bool> *bits, mpz_class r);
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
    cout << "d: " << sk.d << endl;
    if (rop == true)
        cout << "true" << endl;
    else if (rop == false)
        cout << "false" << endl;
    else
        cout << "error" << endl;
    return 0;
}
// mpz_class //
mpz_class urandomm(gmp_randstate_t state, const mpz_class p)
{
    mpz_class r;
    mpz_urandomm(r.get_mpz_t(), state, p.get_mpz_t());
    return r;
}
mpz_class mod_inv(mpz_class x, mpz_class mod)
{
    mpz_class r;
    mpz_invert(r.get_mpz_t(), x.get_mpz_t(), mod.get_mpz_t());
    return r;
}
int cmp(mpz_class A, mpz_class B)
{
    int r;
    r = mpz_cmp(A.get_mpz_t(), B.get_mpz_t());
    return r;
}
mpz_class mod(mpz_class base, mpz_class mod)
{
    mpz_class r;
    mpz_mod(r.get_mpz_t(), base.get_mpz_t(), mod.get_mpz_t());
    return r;
}
////// ECDH //////
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
void bits_inv(vector<bool> *bits, mpz_class r)
{
    for (; r > 0; r = r / 2) // 20=>10100(2)가 나와야 하는데 00101으로 넣어짐
    {
        (*bits).push_back(r % 2 == 1);
    }
}
void EC_mult(EC E, Point *R, Point P, mpz_class r)
{
    vector<bool> v;
    bits_inv(&v, r); // 역순으로 구해진다.  20 => 10100(2)나와야 하는데  00101이 나옴
    *R = P;
    int n = v.size();
    for (; n > 1; n--)
    {
        EC_double(E, R, *R);
        if (v.at(n - 2) == 1) // 1이 true이니깐
        {
            EC_add(E, R, *R, P);
        }
    }
}
//////////
/////ECDSA 전자서명 알고리즘 구현 //////
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
    do
    {
        sk->d = urandomm(state, sk->n);
    } while (sk->d == 0);
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
        do
        {
            k = urandomm(state, sk.n); // 1~n 사이의 값
        } while (k == 0);
        EC_mult(sk.E, &R, sk.G, k);
        sig.S1 = mod(R.x, sk.n);
    } while (sig.S1 == 0); // (x1 mod n =0 이면 go back을 한다. )
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
