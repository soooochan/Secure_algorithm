#include <iostream>
#include <vector>

using namespace std;

void to_bits(vector<int> &bits, int x);
int powm(int base, int exp, int mod);
bool is_primitive(int base, int mod);
void primitive_root(vector<int> &p_roots, int mod);

void print_vector(vector<int> &vec)
{
    for (int &v : vec)
        cout << v << " ";
    cout << endl;
}

int main()
{
    int p = 41;
    vector<int> p_r;
    primitive_root(p_r, p);

    int g = p_r.at(5);

    int a_sk = 11;
    int b_sk = 9;

    int a_temp = powm(g, a_sk, p);
    int b_temp = powm(g, b_sk, p);

    int a_pk = powm(b_temp, a_sk, p);
    int b_pk = powm(a_temp, b_sk, p);

    if (a_pk == b_pk)
        cout << "a_pk == b_pk => success!" << endl;

    return 0;
}

void to_bits(vector<int> &bits, int x)
{
    while (x > 0)
    {
        bits.insert(bits.begin(), x % 2);
        x /= 2;
    }
}
int powm(int base, int exp, int mod)
{
    vector<int> bits;
    to_bits(bits, exp);

    int result = base;
    for (int i = 1; i < bits.size(); i++)
    {
        result = (result * result) % mod;
        if (bits.at(i) == 1)
            result = (result * base) % mod;
    }

    return result;
}
bool is_primitive(int base, int mod)
{
    int tmp = base; // 'base' is same as 'base % mod'
    int i = 1;
    do
    {
        tmp = (tmp * base) % mod;
        i++;
    } while (tmp != base);

    return i == mod;
}
void primitive_root(vector<int> &p_roots, int mod)
{
    for (int i = 2; i < mod; i++)
    {
        if (is_primitive(i, mod))
            p_roots.push_back(i);
    }
}
