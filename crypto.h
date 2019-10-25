// Package: Crypto-PAn 1.0
// File: crypto.cpp
// Last Update: Aug 8, 2005
// Author: Jinliang Fan, David Stott (stott@lucent.com)

#ifndef CRYPTO_H
#define CRYPTO_H

#include <sys/types.h>
#include <openssl/evp.h>

class Crypto
{

  protected:
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;
    const char* ciphername; /** Openssl ciphername (e.g., aes-192-ecb) */
    int keylen; /** key length in bytes */

    int dir; /** 1 to encrypt, 0 to decrypt */
    unsigned char* iv; /** initial vector (IV) */
    unsigned char* key; /** the session key */
    unsigned char* other; /** additional application-specific data */

    int initialized;

  public:

    Crypto( );
    Crypto(  const char* ciphername, const unsigned char* key, const unsigned char* iv );
    ~Crypto();

    int SetCipher( const char* _ciphername );
    void SetKey( const unsigned char* _key );
    void SetIV( const unsigned char* _iv );
    void SetDir( int _dir );

    int GetKeyLength(void) { return EVP_CIPHER_key_length( cipher ); };
    int GetIVLength(void) { return EVP_CIPHER_iv_length( cipher ); };
    size_t GetBlockSize(void) { return  EVP_CIPHER_block_size( cipher ); };
    int GetMode(void) { return EVP_CIPHER_mode( cipher ); };
    int EncryptInit(void);
    int EncryptUpdate( unsigned char *out, int &outl, const unsigned char *in, int inl );
    int EncryptFinal( unsigned char *out, int &outl );

};


#endif // #ifndef CRYPTO_H
