#define CRYPTO_ITERATIONS 1 
#define PRECOMPUTE_BITSLICING 0 
#define USE_HARDWARE_CRYPTO 0


#if (!defined _RAINBOW_REF) && (!defined _RAINBOW_M4)
    #define _RAINBOW_M4
#endif

#if (!defined _RAINBOW_CLASSIC) && (!defined  _RAINBOW_COMPRESSED)
    #define _RAINBOW_COMPRESSED
#endif


//TODO for new variant api.h and sign.c need to be adapted for sk_seed argument, better way to do this?
#if defined _RAINBOW_M4
    #if defined _RAINBOW_CLASSIC
        #include "rainbowm4/crypto_sign/rainbowI-classic/m4/api.h"
        #include "rainbowm4/crypto_sign/rainbowI-classic/m4/api_config.h"
        #include "rainbowm4/crypto_sign/rainbowI-classic/m4/rainbow_keypair.h"
        #include "rainbowm4/crypto_sign/rainbowI-classic/m4/rainbow.h"
    #elif defined _RAINBOW_COMPRESSED
        #include "rainbowm4/crypto_sign/rainbowI-compressed/m4/api.h"
        #include "rainbowm4/crypto_sign/rainbowI-compressed/m4/rainbow_keypair.h"
        #include "rainbowm4/crypto_sign/rainbowI-compressed/m4/rainbow.h"
    #else
        #error define _RAINBOW_CLASSIC or _RAINBOW_COMPRESSED
    #endif
#elif defined _RAINBOW_REF
    #if defined _RAINBOW_CLASSIC
        #include "rainbowm4/crypto_sign/rainbowI-classic/ref/api.h"
        #include "rainbowm4/crypto_sign/rainbowI-classic/ref/rainbow_keypair.h"
        #include "rainbowm4/crypto_sign/rainbowI-classic/ref/rainbow.h"
    #elif defined _RAINBOW_COMPRESSED
        #include "rainbowm4/crypto_sign/rainbowI-compressed/ref/api.h"
        #include "rainbowm4/crypto_sign/rainbowI-compressed/ref/rainbow_keypair.h"
        #include "rainbowm4/crypto_sign/rainbowI-compressed/ref/rainbow.h"
    #else 
        #error define _RAINBOW_CLASSIC or _RAINBOW_COMPRESSED
    #endif
#endif



