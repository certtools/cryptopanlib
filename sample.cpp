// Package: Crypto-PAn 1.0
// File: sample.cpp
// Last Update: Aug 8, 2005
// Author: Jinliang Fan

#include <stdlib.h>
#include <stdio.h>
#include "panonymizer.h"
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc, char * argv[]) {
    // Provide your own 256-bit key here
    unsigned char my_key[32] = 
    {21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,
     216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2};

    FILE * f;

    // Create an instance of PAnonymizer with the key
    PAnonymizer my_anonymizer(my_key);

    float packet_time;
    unsigned int packet_size;
    char packet_addr[100];

    if (argc != 2) {
      fprintf(stderr, "usage: sample raw-trace-file\n");
      exit(-1);
    }
    
    if ((f = fopen(argv[1],"r")) == NULL) {
      fprintf(stderr,"Cannot open file %s\n", argv[1]);
      exit(-2);
    }
       
    //readin and handle each line of the input file
    while  (fscanf(f, "%f", &packet_time) != EOF) {
	struct in_addr inp;
	fscanf(f, "%u", &packet_size);
	fscanf(f, "%s", packet_addr);
	inet_aton(packet_addr,&inp);

	//Anonymize the raw IP
	inp.s_addr = my_anonymizer.anonymize( inp.s_addr );

	//output the sanitized trace
	printf("%6f\t%u\t%s\n",  packet_time, packet_size, inet_ntoa( inp ) );
    }

}
