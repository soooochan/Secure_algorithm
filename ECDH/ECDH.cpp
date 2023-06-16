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

mpz_class mod_inv(mpz_class x, mpz_class p);
int cmp(mpz_class x, mpz_class y);
mpz_class mod(mpz_class n, mpz_class p);
int mpz_div_by_2(mpz_class &q, mpz_class n);
mpz_class urandomm(mpz_class p);

vector<int> to_bits(mpz_class x);
bool is_inf_point(Point P);
bool is_equal_point(Point P, Point Q);
Point EC_add(EC E, Point P, Point Q);
Point EC_double(EC E, Point P);
Point EC_mult(EC E, Point P, mpz_class r);

// System parameter
EC secp256k1 = {0, 7, mpz_class{"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"}};
Point G = {mpz_class{"0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"},
           mpz_class{"0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"}};

Point G2 = {mpz_class{"0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"},
            mpz_class{"0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"}};

Point G3 = {mpz_class{"0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"},
            mpz_class{"0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"}};

Point G7 = {mpz_class{"0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC"},
            mpz_class{"0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA"}};

int main()
{

    cout << "[test] - EC_add" << endl;
    if (is_equal_point(EC_add(secp256k1, G, G2), G3))
        cout << "G + 2G == 3G" << endl;
    else
        cout << "fail" << endl;

    cout << "\n[test] - EC_double" << endl;
    if (is_equal_point(EC_double(secp256k1, G), G2))
        cout << "G double == 2G" << endl;
    else
        cout << "fail" << endl;

    cout << "\n[test] - EC_mult" << endl;
    if (is_equal_point(EC_mult(secp256k1, G, mpz_class{7}), G7))
        cout << "G * 7 == 7G" << endl;
    else
        cout << "fail" << endl;

    cout << "\n------- Diffie Hellman key exchange -------\n"
         << endl;
    mpz_class a, b;
    Point temp_a, temp_b, a_key, b_key;

    a = urandomm(secp256k1.p);
    b = urandomm(secp256k1.p);

    temp_a = EC_mult(secp256k1, G, a);
    temp_b = EC_mult(secp256k1, G, b);

    a_key = EC_mult(secp256k1, temp_b, a);
    b_key = EC_mult(secp256k1, temp_a, b);

    if (is_equal_point(a_key, b_key))
        cout << "--> success" << endl;
    else
        cout << "--> fail" << endl;

    // complie -> gcc ECDH_gmp.cpp -lstdc++ -lgmpxx -lgmp -o ECDH_gmp
    return 0;
}

mpz_class mod_inv(mpz_class x, mpz_class p)
{
    mpz_class result;
    if (mpz_invert(result.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t()) == 0)
        cout << "error. result will be empty" << endl;
    return result;
}
int cmp(mpz_class x, mpz_class y)
{
    return mpz_cmp(x.get_mpz_t(), y.get_mpz_t());
}
mpz_class mod(mpz_class n, mpz_class p)
{
    mpz_class result;
    mpz_mod(result.get_mpz_t(), n.get_mpz_t(), p.get_mpz_t());
    return result;
}
int mpz_div_by_2(mpz_class &q, mpz_class n)
{
    mpz_class r;
    mpz_class d{2};
    mpz_tdiv_qr(q.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), d.get_mpz_t());
    return r.get_ui();
}
mpz_class urandomm(mpz_class p)
{
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    mpz_class result;
    mpz_urandomm(result.get_mpz_t(), state, p.get_mpz_t());
    return result;
}

vector<int> to_bits(mpz_class x)
{
    vector<int> bits;
    int b;
    while (cmp(x, mpz_class{0}))
    {
        b = mpz_div_by_2(x, x);
        bits.insert(bits.begin(), b);
    }
    return bits;
}
bool is_inf_point(Point P)
{
    if (cmp(P.x, mpz_class{0}) == 0 && cmp(P.y, mpz_class{0}) == 0)
        return true;
    else
        return false;
}
bool is_equal_point(Point P, Point Q)
{
    if (cmp(P.x, Q.x) == 0 && cmp(P.y, Q.y) == 0)
        return true;
    else
        return false;
}
Point EC_add(EC E, Point P, Point Q)
{
    if (is_inf_point(P))
        return Q;
    if (is_inf_point(Q))
        return P;

    Point R;

    mpz_class lambda = mod(Q.y - P.y, E.p) * mod_inv(Q.x - P.x, E.p);
    lambda = mod(lambda, E.p);

    R.x = mod(lambda * lambda - P.x - Q.x, E.p);
    R.y = mod(lambda * (P.x - R.x) - P.y, E.p);

    return R;
}
Point EC_double(EC E, Point P)
{
    Point R;

    mpz_class lambda = mod(mod((3 * (P.x * P.x) + E.a), E.p) * mod_inv(2 * P.y, E.p), E.p);

    R.x = mod((lambda * lambda) - 2 * P.x, E.p);
    R.y = mod(lambda * (P.x - R.x) - P.y, E.p);

    return R;
}
Point EC_mult(EC E, Point P, mpz_class r)
{
    Point R;
    vector<int> bits = to_bits(r);

    R = P;

    for (int i = 1; i < bits.size(); i++)
    {
        R = EC_double(E, R);
        if (bits.at(i) == 1)
            R = EC_add(E, R, P);
    }

    return R;
}