// Package: Crypto-PAn 1.0
// File: panonymizer.cpp
// Last Update: Aug 8, 2005
// Author: Jinliang Fan, David Stott (stott@lucent.com)

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "panonymizer.h"


//Constructor
PAnonymizer::PAnonymizer(const u_int8_t * key) :
    m_crypto( "aes-128-ecb", key, NULL ),
    m_blocksize( m_crypto.GetBlockSize() ),
    m_pad( new u_int8_t[m_blocksize] )
{
    int tmp = 0;
    m_crypto.EncryptInit();
    m_crypto.EncryptUpdate( m_pad, tmp, key+m_blocksize, m_blocksize );
}

PAnonymizer::PAnonymizer(const char* ciphername, const u_int8_t * key) :
    m_crypto( ciphername, key, NULL ),
    m_blocksize( m_crypto.GetBlockSize() ),
    m_pad( new u_int8_t[m_blocksize] )

{
    int tmp = 0;
    m_crypto.EncryptInit();
    m_crypto.EncryptUpdate( m_pad, tmp, key+m_blocksize, m_blocksize );
}


//Destructor
PAnonymizer::~PAnonymizer() {
    delete[] m_pad;
}

//Anonymization funtion
u_int32_t
PAnonymizer::anonymize(u_int32_t orig_addr) {

    u_int8_t rin_output[m_blocksize];
    u_int8_t rin_input[m_blocksize];

    u_int32_t result = 0;
    u_int32_t first4bytes_pad;
    int pos;
    int outlen = m_blocksize;

    memset(rin_input, 0, m_blocksize);
    memset(rin_output, 0, m_blocksize);
    memcpy(rin_input, m_pad, m_blocksize);

    // orig_addr starts in network byte order, do all operations in
    // host byte order
    orig_addr = ntohl( orig_addr );

    first4bytes_pad = *(u_int32_t*)m_pad;

    // For each prefixes with length from 0 to 31, generate a bit
    // using the given cipher, which is used as a pseudorandom
    // function here. The bits generated in every rounds are combined
    // into a pseudorandom one-time-pad.
    for ( pos = 0; pos < 32; pos++ ) { 

	u_int32_t mask = -1<<(32-pos);
	u_int32_t newpad = (first4bytes_pad<<pos)|(first4bytes_pad>>(32-pos));
	if (pos == 0 ) {
	    // the compile thinks ( -1<<(32-0) = 0xffffffff instead of 0 )
	    mask = 0;
	    newpad = first4bytes_pad;
	}

	// convert rin_input into network byte order to be encrypted
	*(u_int32_t*)rin_input = htonl( newpad^(orig_addr&mask));

	// Encryption: The cipher is used as pseudorandom
	// function. During each round, only the first bit of
	// rin_output is used.
	if ( m_crypto.EncryptUpdate( rin_output, outlen, rin_input, m_blocksize ) < 0 ) {
	    return 0;
	}

	// treat rin_output, the output of the encryptor as network byte order
	// Combination: the bits are combined into a pseudorandom one-time-pad
	result |= ( (ntohl(*(u_int32_t*)rin_output)) & 0x80000000) >> pos;
    }

    // XOR the orginal address with the pseudorandom one-time-pad
    // convert result to network byte order before returning
    return htonl( result ^ orig_addr );
}

//De-Anonymization funtion
u_int32_t
PAnonymizer::deanonymize(u_int32_t fake_addr) {

    u_int8_t rin_output[m_blocksize];
    u_int8_t rin_input[m_blocksize];

    u_int32_t first4bytes_pad;
    int pos;
    int outlen = m_blocksize;
    u_int32_t orig_addr = ntohl( fake_addr );

    memset(rin_input, 0, sizeof(rin_input));
    memset(rin_output, 0, sizeof(rin_output));
    memcpy(rin_input, m_pad, m_blocksize);

    first4bytes_pad = *(u_int32_t*)m_pad;

    for ( pos = 0; pos < 32; pos++ ) { 

	int mask = -1<<(32-pos);
	u_int32_t newpad = (first4bytes_pad<<pos)|(first4bytes_pad>>(32-pos));
	if (pos == 0 ) {
	    mask = 0;
	    newpad = first4bytes_pad;
	}

	*(u_int32_t*)rin_input = htonl(newpad^(orig_addr&mask));

	if ( m_crypto.EncryptUpdate( rin_output, outlen, rin_input, m_blocksize ) < 0 ) {
	    return 0;
	}

	orig_addr ^= ((ntohl(*(u_int32_t*)rin_output)) & 0x80000000) >> pos;
    }

    return htonl(orig_addr);
}


// reverses the order of the all 32 bits
// Note this is byte-order independent. That is,
// byte_swap(reverse_bits(byte_swap(x))) = reverse_bits(x).
static u_int32_t
reverse_bits( u_int32_t addr )
{
    u_int32_t tmp = 0;
    int i;

    for ( i = 0; i < 32; i++ ) {
        tmp = tmp << 1;
        tmp |= addr&0x1;
        addr = addr>>1;
    }

    return tmp;
}


/**
 * anonymizer function for reverse-prefix-preserving anonmyizer
 */
u_int32_t
PAnonymizer::nonpa_anonymize( u_int32_t orig_addr )
{
    return anonymize( reverse_bits( orig_addr ) );
}


/**
 * de-anonymizer function for reverse-prefix-preserving anonmyizer
 */
u_int32_t
PAnonymizer::nonpa_deanonymize( u_int32_t fake_addr )
{
    return reverse_bits( anonymize( fake_addr ) );
}

