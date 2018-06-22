#include "binarium_hash_v1.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
//#include <iostream>
/*#include <node.h>
#include <node_buffer.h>
#include <v8.h>*/

#include "x11.h"

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

#include "crypto/hashing/streebog/stribog.h"
#include "crypto/hashing/whirlpool/whirlpool.h"

#include "crypto/encryption/gost2015_kuznechik/libgost15/libgost15.h"
#include "crypto/encryption/three_fish/libskein_skein.h"
//#include "openssl/camellia.h"
#include "open_ssl/camellia/camellia.h"

#include "crypto/encryption/salsa20/ecrypt-sync.h"



#define I_ALGORITHM_RECONFIGURATION_TIME_PERIOD_IN_SECONDS 604800    // 600

#define I_PRIME_NUMBER_FOR_MEMORY_HARD_HASHING 3571

#define I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION 32 * 1024
#define I_MEMORY_BLOCK_SIZE_TO_ENCRYPTION_COMPUTATIONS_RATIO 1

const uint32_t GenesisBlock_nTime = 1516957200;

typedef void ( * TCryptographyFunction ) ( const void *, const uint32_t, const void *, void * ); // uint512

#define I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS 14
#define I_AMOUNT_OF_INTERMEDIATE_ENCRYPTION_FUNCTIONS 3

TCryptographyFunction aIntermediateHashFunctions [ I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS ];
TCryptographyFunction aIntermediateEncryptionFunctions [ I_AMOUNT_OF_INTERMEDIATE_ENCRYPTION_FUNCTIONS ];



//---Hashing.-------------------------------------------------------------
void IntermediateHashFunction_Blake ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_blake512_context     ctx_blake;

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, _pData, _iDataSize);
    sph_blake512_close(&ctx_blake, _pResult);
}

void IntermediateHashFunction_BMW ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_bmw512_context       ctx_bmw;

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, _pData, _iDataSize);
    sph_bmw512_close(&ctx_bmw, _pResult);
}

void IntermediateHashFunction_Groestl ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_groestl512_context   ctx_groestl;

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, _pData, _iDataSize);
    sph_groestl512_close(&ctx_groestl, _pResult);
}

void IntermediateHashFunction_JH ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_jh512_context        ctx_jh;

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, _pData, _iDataSize);
    sph_jh512_close(&ctx_jh, _pResult);
}

void IntermediateHashFunction_Keccak ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_keccak512_context    ctx_keccak;

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, _pData, _iDataSize);
    sph_keccak512_close(&ctx_keccak, _pResult);
}

void IntermediateHashFunction_Skein ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_skein512_context     ctx_skein;

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, _pData, _iDataSize);
    sph_skein512_close(&ctx_skein, _pResult);
}

void IntermediateHashFunction_Luffa ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_luffa512_context     ctx_luffa;

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, _pData, _iDataSize);
    sph_luffa512_close(&ctx_luffa, _pResult);
}

void IntermediateHashFunction_Cubehash ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_cubehash512_context  ctx_cubehash;

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, _pData, _iDataSize);
    sph_cubehash512_close(&ctx_cubehash, _pResult);
}

void IntermediateHashFunction_Shavite ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_shavite512_context   ctx_shavite;

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, _pData, _iDataSize);
    sph_shavite512_close(&ctx_shavite, _pResult);
}

void IntermediateHashFunction_Simd ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_simd512_context      ctx_simd;

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, _pData, _iDataSize);
    sph_simd512_close(&ctx_simd, _pResult);
}

void IntermediateHashFunction_Echo ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_echo512_context      ctx_echo;

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, _pData, _iDataSize);
    sph_echo512_close(&ctx_echo, _pResult);
}

void IntermediateHashFunction_GOST_2012_Streebog ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    hash_512 ( ( const unsigned char * ) _pData, _iDataSize, ( unsigned char * ) _pResult );
}

void IntermediateHashFunction_Whirlpool ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    whirlpool_ctx            structureWhirlpoolContext;

    rhash_whirlpool_init ( & structureWhirlpoolContext );
    rhash_whirlpool_update ( & structureWhirlpoolContext, ( const unsigned char * ) _pData, _iDataSize); 
    rhash_whirlpool_final ( & structureWhirlpoolContext, ( unsigned char * ) _pResult);
}

/*inline uint512 IntermediateHashFunction_SWIFFT ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    HashKey key ALIGN;
    HashState state ALIGN;
    SWIFFT_HashData data ALIGN;

    SwiFFT_initState ( state );
    SwiFFT_readKey ( ( const unsigned char * ) _pKey, & key );    
    SwiFFT_readData ( data, ( const unsigned char * ) _pData );
    SwiFFT ( key, state, data );

    memcpy ( _pResult, state, 64 );

    //SwiFFT_printState ( state );
    //SwiFFT_printKey ( key );
    //SwiFFT_printData ( data );
}*/

//---Encryption.----------------------------------------------------------------------
void IntermediateEncryptionFunction_GOST_2015_Kuznechik ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    //uint64_t iIndex = GetUint64IndexFrom512BitsKey ( _pKey, 0 );
    //iIndex = iIndex % chainActive.Height ();

    encryptBlockWithGost15 ( _pKey, ( ( unsigned char * ) _pResult ) );           // _pKey & chainActive [ chainActive.Height () - iIndex ] -> nVersion
    encryptBlockWithGost15 ( _pData, ( ( unsigned char * ) _pResult + 16 ) );     // _pData
    encryptBlockWithGost15 ( _pKey, ( ( unsigned char * ) _pResult + 32 ) );      // _pKey
    encryptBlockWithGost15 ( _pData, ( ( unsigned char * ) _pResult + 48 ) );     // _pData
}

void IntermediateEncryptionFunction_ThreeFish ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    char T[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        
    // Result, Key, Text.
    libskein_threefish_encrypt( ( char * ) _pResult, ( const char * ) _pKey, T, ( const char * ) _pData, 64, 512);
}

void IntermediateEncryptionFunction_Camellia ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    CAMELLIA_KEY stKey;
    Camellia_set_key ( ( const unsigned char * ) _pKey, 256, & stKey ); // userKey    
    Camellia_encrypt ( ( const unsigned char * ) _pData, ( unsigned char * ) _pResult, & stKey );        // in, out, key 
}



inline void HashGenerator_Init () {
    aIntermediateHashFunctions [ 0 ]        = & IntermediateHashFunction_Blake;
    aIntermediateHashFunctions [ 1 ]        = & IntermediateHashFunction_BMW;
    aIntermediateHashFunctions [ 2 ]        = & IntermediateHashFunction_Groestl;
    aIntermediateHashFunctions [ 3 ]        = & IntermediateHashFunction_JH;
    aIntermediateHashFunctions [ 4 ]        = & IntermediateHashFunction_Keccak;
    aIntermediateHashFunctions [ 5 ]        = & IntermediateHashFunction_Skein;
    aIntermediateHashFunctions [ 6 ]        = & IntermediateHashFunction_Luffa;
    aIntermediateHashFunctions [ 7 ]        = & IntermediateHashFunction_Cubehash;
    aIntermediateHashFunctions [ 8 ]        = & IntermediateHashFunction_Shavite;
    aIntermediateHashFunctions [ 9 ]        = & IntermediateHashFunction_Simd;
    aIntermediateHashFunctions [ 10 ]       = & IntermediateHashFunction_Echo;
    aIntermediateHashFunctions [ 11 ]       = & IntermediateHashFunction_GOST_2012_Streebog;
    aIntermediateHashFunctions [ 12 ]       = & IntermediateHashFunction_Whirlpool;
    //aIntermediateHashFunctions [ 13 ]       = & IntermediateHashFunction_SWIFFT;
    aIntermediateHashFunctions [ 13 ]       = & IntermediateHashFunction_GOST_2012_Streebog;

    aIntermediateEncryptionFunctions [ 0 ]         = & IntermediateEncryptionFunction_GOST_2015_Kuznechik;
    aIntermediateEncryptionFunctions [ 1 ]         = & IntermediateEncryptionFunction_ThreeFish;
    aIntermediateEncryptionFunctions [ 2 ]         = & IntermediateEncryptionFunction_Camellia;
}



inline uint64_t GetUint64IndexFrom512BitsKey ( const unsigned char * _pKey, int pos ) {
    //const uint8_t* ptr = ( const uint8_t * ) _pKey + pos * 8;
    //return ((uint64_t)ptr[0]) | \
           ((uint64_t)ptr[1]) << 8 | \
           ((uint64_t)ptr[2]) << 16 | \
           ((uint64_t)ptr[3]) << 24 | \
           ((uint64_t)ptr[4]) << 32 | \
           ((uint64_t)ptr[5]) << 40 | \
           ((uint64_t)ptr[6]) << 48 | \
           ((uint64_t)ptr[7]) << 56;

    uint64_t * pAdress = ( uint64_t * ) ( _pKey + pos );
    return pAdress [ 0 ] ^ pAdress [ 1 ] ^ pAdress [ 2 ] ^ pAdress [ 3 ] ^
           pAdress [ 4 ] ^ pAdress [ 5 ] ^ pAdress [ 6 ] ^ pAdress [ 7 ];

}

uint1024_XOROperator ( const char * _pDestinationData, const uint32_t _iDestinationOffsetInBytes, const unsigned char * _pData ) {
    uint32_t i;

    uint64_t * pDestinationNumbers = ( uint64_t * ) ( _pDestinationData + _iDestinationOffsetInBytes );
    uint64_t * pSourceNumbers = ( uint64_t * ) _pData;

    for ( i = 0; i < 512 / 8 / 8; i ++ ) { // 8 bits in byte and 8 bytes in uint64_t.
        //fprintf(stdout, "uint512.XOROperator () : %i .\n", i * 8 );

        /** ( ( uint64_t * ) ( begin () + _iDestinationOffsetInBytes + i * 8 ) ) = 
            * ( ( uint64_t * ) ( begin () + _iDestinationOffsetInBytes + i * 8 ) ) ^
            * ( ( uint64_t * ) ( _pData + i * 8 ) );*/

        pDestinationNumbers [ i ] = pDestinationNumbers [ i ] ^ pSourceNumbers [ i ];

    } //-for

}



void bin2hex(char *s, const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
}



void Binarium_hash_v1_hash_Implementation(const char* input, char* output, uint32_t len, uint32_t _iTimeFromGenesisBlock )
{
    /*sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;

    sph_luffa512_context		ctx_luffa1;
    sph_cubehash512_context		ctx_cubehash1;
    sph_shavite512_context		ctx_shavite1;
    sph_simd512_context		ctx_simd1;
    sph_echo512_context		ctx_echo1;*/

    //these uint512 in the c++ source of the client are backed by an array of uint32
    //uint32_t hashA[16], hashB[16];

    /*sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, len);
    sph_blake512_close (&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 64);
    sph_skein512_close (&ctx_skein, hashB);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);
	
    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashB, 64);
    sph_luffa512_close (&ctx_luffa1, hashA);	
	
    sph_cubehash512_init (&ctx_cubehash1); 
    sph_cubehash512 (&ctx_cubehash1, hashA, 64);   
    sph_cubehash512_close(&ctx_cubehash1, hashB);  
	
    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, hashB, 64);   
    sph_shavite512_close(&ctx_shavite1, hashA);  
	
    sph_simd512_init (&ctx_simd1); 
    sph_simd512 (&ctx_simd1, hashA, 64);   
    sph_simd512_close(&ctx_simd1, hashB); 
	
    sph_echo512_init (&ctx_echo1); 
    sph_echo512 (&ctx_echo1, hashB, 64);   
    sph_echo512_close(&ctx_echo1, hashA);*/

    //memcpy(output, hashA, 32);



    uint32_t * p_nBits = ( input + 4 + 32 + 32 + 4 );

    /*uint512 hash[11];
    uint512 uint512AdditionalHash;

    uint512 uint512ChainBlockData;

    uint1024 uint1024CombinedHashes;*/
    uint32_t hash [ 11 ] [ 16 ];
    uint32_t uint512AdditionalHash [ 16 ];
    uint32_t uint1024CombinedHashes [ 32 ];

    uint64_t iIndexOfBlcok;
    uint64_t iWeekNumber;
    uint64_t iIndexFromWeekChangeBlock;
    uint64_t iIndex;

    uint32_t i = 0;

    char block_str[200];
    char hash_str[129];
    char hash_1024_str[257];



    // Important!
    memset ( hash, 0, sizeof(hash) ); 



    bin2hex ( hash_str, ( unsigned char * ) input, 80 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : block_str : %s.\n", block_str );

    // blake512
    aIntermediateHashFunctions [ 0 ] ( input, len, NULL, hash [ 0 ] );
    bin2hex ( hash_str, ( unsigned char * ) hash [ 0 ], 64 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : blake512 : %s.\n", hash_str );

    // bmw512
    aIntermediateHashFunctions [ 1 ] ( hash [ 0 ], 64, NULL, uint512AdditionalHash );
    bin2hex ( hash_str, ( unsigned char * ) uint512AdditionalHash, 64 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : bmw512 : %s.\n", hash_str );

    iWeekNumber = _iTimeFromGenesisBlock / I_ALGORITHM_RECONFIGURATION_TIME_PERIOD_IN_SECONDS * I_ALGORITHM_RECONFIGURATION_TIME_PERIOD_IN_SECONDS;
    iIndex = ( iWeekNumber + * p_nBits ) % I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS;
    aIntermediateHashFunctions [ iIndex ] ( uint512AdditionalHash, 64, NULL, hash [ 1 ] );
    bin2hex ( hash_str, ( unsigned char * ) hash [ 1 ], 64 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : aIntermediateHashFunctions 1 : %s.\n", hash_str );

    // groestl512
    aIntermediateHashFunctions [ 2 ] ( hash [ 1 ], 64, NULL, hash [ 2 ] );
    bin2hex ( hash_str, ( unsigned char * ) hash [ 2 ], 64 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : groestl512 : %s.\n", hash_str );

    // skein512
    aIntermediateHashFunctions [ 5 ] ( hash [ 2 ], 64, NULL, ( (unsigned char *) uint1024CombinedHashes + 64 ) );
    bin2hex ( hash_1024_str, ( unsigned char * ) uint1024CombinedHashes, 128 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : skein512 : %s.\n", hash_1024_str );

    //-Streebog.--------------------------------------
    // jh512    

    aIntermediateHashFunctions [ 3 ] ( ( (unsigned char *) uint1024CombinedHashes + 64 ), 64, NULL, uint1024CombinedHashes );
    bin2hex ( hash_1024_str, ( unsigned char * ) uint1024CombinedHashes, 64 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : jh512 : %s.\n", hash_1024_str );



    ECRYPT_ctx structECRYPT_ctx;

    unsigned char aMemoryArea [ I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION ];
    memset ( aMemoryArea, 0, I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION );

    ECRYPT_keysetup ( & structECRYPT_ctx, hash[1], ECRYPT_MAXKEYSIZE, ECRYPT_MAXIVSIZE );
    ECRYPT_ivsetup ( & structECRYPT_ctx, hash[2] );

    uint64_t iWriteIndex;

    // Amplifying data and making random write accesses to memory.
    // Block size is 64 bytes. ECRYPT_BLOCKLENGTH .
    // Hash size is 64 bytes.
    for ( i = 0; i < I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION / ( 64 ) / 2; i ++ ) {
        iWriteIndex =
            (
                //  % I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION here is to prevent integer overflow
                // on subsequent addition operation.
                GetUint64IndexFrom512BitsKey ( ( (unsigned char *) uint1024CombinedHashes + 64 ), 0 ) % I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION +
                i * I_PRIME_NUMBER_FOR_MEMORY_HARD_HASHING )
            %
            ( I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION - 8 * ECRYPT_BLOCKLENGTH );

        // From previous encryption result in memory to next encryption result in memory.
        ECRYPT_encrypt_blocks ( & structECRYPT_ctx,
            ( (unsigned char *) uint1024CombinedHashes + 64 ),
            & ( aMemoryArea [ iWriteIndex ] ),
            1 );  // 8

        //uint1024CombinedHashes.XOROperator ( 64, & ( aMemoryArea [ iWriteIndex ] ) );
        uint1024_XOROperator ( uint1024CombinedHashes, 64, & ( aMemoryArea [ iWriteIndex ] ) );

    } //-for
    
    for ( i = 0; i < I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION / 64; i ++ ) {
        //uint1024CombinedHashes.XOROperator ( 64, & ( aMemoryArea [ i * 64 ] ) );
        uint1024_XOROperator ( uint1024CombinedHashes, 64, & ( aMemoryArea [ i * 64 ] ) );

    } //-for

    bin2hex ( hash_1024_str, ( unsigned char * ) uint1024CombinedHashes, 64 );
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : Memory-hard hashing function : %s.\n", hash_1024_str );

    //-Whirlpool--------------------------------------
    // keccak512
    aIntermediateHashFunctions [ 4 ] ( uint1024CombinedHashes, 128, NULL, hash[5] );

    //-SWIFFT.----------------------------------------
    // luffa512
    aIntermediateHashFunctions [ 6 ] ( hash[5], 64, NULL, hash[6] );

    // cubehash512
    aIntermediateHashFunctions [ 7 ] ( hash[6], 64, NULL, hash[7] );

    //-GOST 2015_Kuznechik.---------------------------
    memcpy ( hash [ 6 ], hash [ 7 ], 64 );
    iIndex = ( iWeekNumber + * p_nBits ) % I_AMOUNT_OF_INTERMEDIATE_ENCRYPTION_FUNCTIONS;
    aIntermediateEncryptionFunctions [ iIndex ] ( hash[6], 64, hash[0], hash[7] );

    // shavite512
    aIntermediateHashFunctions [ 8 ] ( hash[7], 64, NULL, hash[8] );

    //---ThreeFish.----------------------------------

    // simd512
    aIntermediateHashFunctions [ 9 ] ( hash[8], 64, NULL, uint512AdditionalHash );

    iIndex = ( iWeekNumber + * p_nBits + 10 ) % I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS;
    aIntermediateHashFunctions [ iIndex ] ( uint512AdditionalHash, 64, NULL, hash[9] );

    //---Camellia.-----------------------------------    

    // echo512
    aIntermediateHashFunctions [ 10 ] ( hash[9], 64, NULL, hash[10] );



    //return hash[10].trim256();
    memcpy ( output, hash[10], 32 );

    bin2hex ( hash_str, ( unsigned char * ) output, 32 );
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : resulting hash : %s.\n", hash_str );
    //std::
    //cout << "DEBUG: Binarium_hash_v1_hash_Implementation () : resulting hash : " << hash_str << " .\n";
    //isolate->ThrowException(Exception::TypeError(
    //    String::NewFromUtf8(isolate, "Wrong number of arguments")));
    fprintf ( stdout, "DEBUG: Binarium_hash_v1_hash_Implementation () : resulting hash : %s.\n", hash_str );

}

void Binarium_hash_v1_hash(const char* input, char* output, uint32_t len)
{
    HashGenerator_Init ();

    char Data [ 200 ];
    memset ( Data, 0, sizeof ( Data ) );

    uint32_t iTimeFromGenesisBlock;
    //uint32_t iAlgorithmSelector;
    //uint32_t iHashFunctionsAmount;
    //uint32_t * p_nTime = ( input + 4 + 32 + 32 );
    uint32_t * p_nTime = ( Data + 4 + 32 + 32 );

    iTimeFromGenesisBlock = * p_nTime - GenesisBlock_nTime;
    //iHashFunctionsAmount = 2;
    //iAlgorithmSelector = iTimeFromGenesisBlock < 3528000 ? 0 : 1;

    //return (this->*(aHashFunctions[iAlgorithmSelector]))( pPrevBlockIndex, iTimeFromGenesisBlock );
    //if ( iTimeFromGenesisBlock >= 3528000 ) {
        //Binarium_hash_v1_hash_Implementation ( input, output, len, iTimeFromGenesisBlock );
    Binarium_hash_v1_hash_Implementation ( Data, output, len, iTimeFromGenesisBlock );

    /*} else
        x11_hash ( input, output, len );*/

}