#include <iostream>
#include <gmpxx.h>

using namespace std;

// ---- gmp 라이브러리에서 제공하는 함수들의 래퍼(wrapper)함수들 ------
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod); // r 에 m^e mod k 저장
mpz_class urandomm(const mpz_class n);                        //  urandomm 함수를 이용해서 n보다 작은 랜덤값 생성
int cmp(mpz_class A, mpz_class B);                            // 공유하는 비밀키 계산 

// -----------------------전역변수(공개키)--------------------------
// RFC7919에서 제공하는 소수p와 생성원 g사용(계산이 효율적이고 안전성은 그대로)
mpz_class p{"0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF"};
mpz_class g = 2;
// ----------------------------------------------------------------

int main()
{
    // 사용할 변수들 미리 선언
    mpz_class a, b, a_temp, b_temp, a_key, b_key;

    // 랜덤한 값으로 a, b의 개인키 생성
    a = urandomm(p);
    b = urandomm(p);

    // 중간값: g의 개인키 승 모드 p 계산
    a_temp = powm(g, a, p);
    b_temp = powm(g, b, p);

    // 중간값을 교환하여 공유하는 공개키 생성
    a_key = powm(b_temp, a, p);
    b_key = powm(a_temp, b, p);

    // 생성한 공개키가 같은지 확인
    if (cmp(a_key, b_key) == 0)
        cout << "success!" << endl;
    else
        cout << "fail.." << endl;

    // complie -> gcc DH_gmp.cpp -lstdc++ -lgmpxx -lgmp -o DH_gmp
    return 0;
}

mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod)
{
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}
mpz_class urandomm(const mpz_class n)
{
    // 매번 지정해야하는 randstate를 함수내에서 매번 초기화하도록 함
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    mpz_class result;
    mpz_urandomm(result.get_mpz_t(), state, n.get_mpz_t());
    return result;
}
int cmp(mpz_class A, mpz_class B)
{
    return mpz_cmp(A.get_mpz_t(), B.get_mpz_t());
}