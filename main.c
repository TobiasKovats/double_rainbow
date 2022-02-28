#include <stdint.h>
#include <stddef.h>

#include "rainbow_api.h"

#include "utils_prng.h"
#define PASTER(x, y) x####y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)


// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_BYTES          NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_ALGNAME        NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_sign_keypair NAMESPACE(crypto_sign_keypair)
#define MUPQ_crypto_sign NAMESPACE(crypto_sign)
#define MUPQ_crypto_sign_open NAMESPACE(crypto_sign_open)
#define MUPQ_crypto_sign_signature NAMESPACE(crypto_sign_signature)
#define MUPQ_crypto_sign_verify NAMESPACE(crypto_sign_verify)

#define MLEN 32

#define LCDCW1_ADDR       0xc000
#define READ_LCDCW1()     (*(volatile uint8_t *)LCDCW1_ADDR)
#define WRITE_LCDCW1(val) ((*(volatile uint8_t *)LCDCW1_ADDR) = (val))

uint8_t pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
uint8_t sk[MUPQ_CRYPTO_SECRETKEYBYTES];
uint8_t sk_seed[LEN_SKSEED];
uint8_t pk_seed[LEN_PKSEED];
uint8_t m[MLEN];
uint8_t sm[MLEN + MUPQ_CRYPTO_BYTES];
size_t mlen;
size_t smlen;


prng_t prng;

int main(void) {
    prng_t * prng0 = &prng;
    prng_gen(prng0, sk_seed, LEN_SKSEED);
    prng_gen(prng0, m, MLEN);
    MUPQ_crypto_sign_keypair(pk,sk, pk_seed, sk_seed);
    uint8_t ret_sign = MUPQ_crypto_sign(sm, &smlen, m, MLEN, sk);
    uint8_t ret_verify = MUPQ_crypto_sign_open(m, &mlen, m, smlen, pk);
 

}