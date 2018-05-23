// Package: Crypto-PAn 1.0
// File: cryptopanlib.cpp
// Last Update: May 13th  2018
// Author: Aaron Kaplan <kaplan@cert.at>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "panonymizer.h"
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cryptopanlib.h"

static char key[32] = "";
static PAnonymizer *anonymizer;

extern "C" int init(const char *_key) {
    if (strlen(_key) != 32) {
        fprintf(stderr, "cryptopanlib: key length invalid\n");
        return -1;
    }
    bzero(key, sizeof(key));
    strncpy(key, _key, sizeof(key)); 
    anonymizer = new PAnonymizer((const unsigned char*)key);
    return 0;
}


extern "C" unsigned int anonymize(unsigned int ip) {
    // fprintf(stderr, "got an unsigned int: %u\n", ip);
    return anonymizer->anonymize( ip );
}

extern "C" unsigned int anonymize_str(const char *ip_str) {
    // fprintf(stderr, "got an const char*: %s\n", ip_str);
    // try to convert to int
    struct sockaddr_in sa;
    int rc = inet_pton(AF_INET, ip_str, &(sa.sin_addr));
    if (1 != rc) {
        fprintf(stderr, "not an IP address: %s\n", ip_str);
        return 0;
    }
    return anonymizer->anonymize( ntohl(sa.sin_addr.s_addr ) );
}
