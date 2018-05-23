// Package: Crypto-PAn 1.0
// File: crypto.cpp
// Last Update: Aug 8, 2005
// Author: Jinliang Fan, David Stott (stott@lucent.com)

#include <string.h>
#include <stdlib.h>

#include "crypto.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include <iostream>


static BIO* bio_err = NULL;
static int Ciphersloaded = 0;

static BIO* 
init_bio_err()
{
    if (bio_err == NULL && (bio_err=BIO_new(BIO_s_file())) != NULL) {
        BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
        ERR_load_crypto_strings();
    }
    return bio_err;
}

void
bio_err_print_errors()
{
    init_bio_err();
    ERR_print_errors( bio_err );
}

/**
 * initializes ciphernames (i.e., calls OpenSSL_add_all_ciphers), if needed
 */
static void
init_ciphernames()
{
    if ( Ciphersloaded == 0 ) {
        OpenSSL_add_all_ciphers();
        Ciphersloaded = 1;
    }
}



Crypto::Crypto()
{
    initialized = 0;
    dir = 1;
    if ( bio_err == NULL ) {
        init_bio_err();
    }
}

Crypto::Crypto( const char* _ciphername, const unsigned char* _key, const unsigned char* _iv  )
{
    initialized = 0;
    dir = 1;

    if ( SetCipher( _ciphername ) ) {
        return;
    }

    SetKey( _key );

    SetIV( _iv );

}

Crypto::~Crypto()
{
    delete key;
    key = NULL;

    delete iv;
    iv = NULL;

    EVP_CIPHER_CTX_cleanup( ctx );
}

int
Crypto::SetCipher( const char* _ciphername )
{
    ciphername = strdup(_ciphername);

    init_ciphernames();

    /* finds cipher structure matching session key's ciphername */
    if ( (cipher = EVP_get_cipherbyname( ciphername )) == NULL ) {
        std::cerr << "Crypto::SetCipher(): Unable to understand cipher "<< ciphername << std::endl;
        return -1;
    }

    initialized = 0;

    return 0;
}

// void
// Crypto::Initialize()
// {
//     if ( initialized == 0 ) {

// 	EVP_CIPHER_CTX_init( ctx );

// 	if ( EVP_CipherInit_ex( ctx, cipher, NULL, key, iv, dir ) != 1 ) {
// 	    std::cerr << "Crypto::Initialize(): Error on EVP_CipherInit_ex" << std::endl;
// 	    return;
// 	}

// 	initialized = 1;

//     }
// }

void
Crypto::SetDir( int _dir )
{
    dir = _dir;
}

void
Crypto::SetKey( const unsigned char* _key )
{
    if ( _key != NULL ) {
        key = new unsigned char[GetKeyLength()];
        memcpy( key, _key, GetKeyLength() );
    }
}


void
Crypto::SetIV( const unsigned char* _iv )
{
    if ( _iv != NULL  ) {
        iv = new unsigned char[GetIVLength()];
        memcpy( iv, _iv, GetIVLength() );
    }
}



int
Crypto::EncryptInit(void)
{
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init( ctx );

    if ( EVP_CipherInit_ex( ctx, cipher, NULL, key, iv, dir ) != 1 ) {
        std::cerr << "Crypto::Initialize(): Error on EVP_CipherInit_ex" << std::endl;
        return -1;
    }

    initialized = 1;

    return 0;
}

int
Crypto::EncryptUpdate( unsigned char *out, int &outl, const unsigned char *in, int inl )
{
    if ( EVP_CipherUpdate( ctx, out, &outl, in, inl ) == 0 ) {
        std::cerr << "Crypto::CipherUpdate() failed" << std::endl;
        return -1;
    }
    return 0;
}


int
Crypto::EncryptFinal( unsigned char *out, int &outl )
{
    if ( EVP_CipherFinal_ex( ctx, out, &outl ) == 0 ) {
        std::cerr << "Crypto::EncryptFinal() failed" << std::endl;
        return -1;
    }
    return 0;
}





