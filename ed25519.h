#pragma once

#define ED25519_PRIVATE_SIZE 32
#define ED25519_PUBLIC_SIZE 32
#define ED25519_SCALAR_SIZE 32
#define ED25519_POINT_SIZE 32
#define ED25519_SIG_SIZE 64

void ed25519_mulbase(uint8_t *point, uint8_t *scalar);

// taken from libsodium code below ...
//
typedef int32_t fe[10];

typedef struct {
    fe YplusX;
    fe YminusX;
    fe Z;
    fe T2d;
} ge_cached;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p1p1;

typedef struct {
    fe yplusx;
    fe yminusx;
    fe xy2d;
} ge_precomp;
typedef struct {
    fe X;
    fe Y;
    fe Z;
} ge_p2;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p3;

void fe_invert(fe out,const fe z);
void fe_sq(fe h,const fe f);
void fe_mul(fe h,const fe f,const fe g);
void fe_tobytes(unsigned char *s,const fe h);
void fe_sq2(fe h,const fe f);
void fe_add(fe h,const fe f,const fe g);
void fe_sub(fe h,const fe f,const fe g);
void fe_neg(fe h,const fe f);
void fe_copy(fe h,const fe f);
void fe_1(fe h);
void fe_0(fe h);
void fe_cmov(fe f,const fe g,unsigned int b);
void ge_p3_0(ge_p3 *h);
unsigned char negative(signed char b);
void cmov(ge_precomp *t,const ge_precomp *u,unsigned char b);
unsigned char equal(signed char b,signed char c);
void ge_select(ge_precomp *t,int pos,signed char b);
void ge_madd(ge_p1p1 *r,const ge_p3 *p,const ge_precomp *q);
extern void ge_p1p1_to_p3(ge_p3 *r,const ge_p1p1 *p);
extern void ge_p1p1_to_p2(ge_p2 *r,const ge_p1p1 *p);
void ge_p2_dbl(ge_p1p1 *r,const ge_p2 *p);
void ge_p3_dbl(ge_p1p1 *r,const ge_p3 *p);
extern void ge_p3_to_p2(ge_p2 *r,const ge_p3 *p);
void ge_p3_tobytes(unsigned char *s,const ge_p3 *h);
void ge_scalarmult_base(ge_p3 *h,const unsigned char *a);
void ge_double_scalarmult_vartime(ge_p2 *r,const unsigned char *a,
                const ge_p3 *A,const unsigned char *b);
void ge_precomp_0(ge_precomp *h);
void sc_reduce(unsigned char *s);
void sc_muladd(unsigned char *s,const unsigned char *a,
                const unsigned char *b,const unsigned char *c);

void slide(signed char *r,const unsigned char *a);
void ge_msub(ge_p1p1 *r,const ge_p3 *p,const ge_precomp *q);
int ge_frombytes_negate_vartime(ge_p3 *h,const unsigned char *s);
void ge_add(ge_p1p1 *r,const ge_p3 *p,const ge_cached *q);
extern void ge_p3_to_cached(ge_cached *r,const ge_p3 *p);
void ge_p2_0(ge_p2 *h);
void ge_sub(ge_p1p1 *r,const ge_p3 *p,const ge_cached *q);
void fe_frombytes(fe h,const unsigned char *s);
void fe_pow22523(fe out,const fe z);
int fe_isnonzero(const fe f);
int crypto_verify_32(const unsigned char *x, const unsigned char *y);
void ge_tobytes(unsigned char *s,const ge_p2 *h);
