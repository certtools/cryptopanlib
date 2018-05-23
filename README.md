# cryptopanlib
Version of David Stott's Lucent Crypto-PAn lib: useable for Python ctypes loading


Overview
---------

This README describes a modification of the Lucent C++ Implementation by
David Stott of CryptoPAn.
You can find the original Lucent's extension at https://www.cc.gatech.edu/computing/Networking/projects/cryptopan/lucent.shtml

These changes were done by Aaron Kaplan <kaplan@cert.at>
  * make a .so library out of it: cryptopanlib.so
  * make a sample python wrapper around the cryptopanlib.so: panonymize.py

Aaron Kaplan's Code is released under an AGPL license version 3 or higher. The other parts of the code remain
at their original copyright.
Please see the headers in each file.


Installation instructions
--------------------------

You will need
  * openssl development files: ``apt-get install  libssl-dev`` (https://packages.debian.org/stretch/libssl-dev)
  * C++: `` apt-get install build-essential``

Type "make"

Test via:
```
$ python panonymize.py
loaded cryptopanlib @ <CDLL 'cryptopanlib.so', handle 56058db404f0 at 0x7faaaaaaa278>

encrypted 100000 ints in 1.541809320449829 seconds. rate = 64858.863332610155
```


Copy the cryptopanlib.so to the place where you need it.

This code was tested under Debian Stretch. It does not work on OS X yet.

All bug reports should go to kaplan@cert.at please.




--- snip --- original README attached below --- snip ----

1. Introduction

This is an implementation of the cryptography based prefix-preserving trace
anonymization technique described in "Prefix-Preserving IP Address
Anonymization: Measurement-based Security Evaluation and a New Cryptography-
based Scheme" authored by Jun Xu, Jinliang Fan, Mostafa Ammar and Sue Moon.
In this implementation, we use Rijndael cipher(AES algorithm) as underlying
pseudorandom function.


2. Files

The package contains following files

README      this file
DISCLAIMER      standard disclaimer
rijndael.h
rijndael.cpp    Szymon Stefanek(stefanek@tin.it)'s C++ implementation of the
            Rijndael cipher(now becomes AES) based on Vincent Rijmen and
        K.U.Leuven implementation 2.4.
panonymizer.h
panonymizer.cpp Our implementation of the prefix-preserving IP anonymizer
        using Rijndael cipher as pseudorandom function. The two files
        implement class PAnonymizer. Class PAnonymizer needs a 256-bit
        key for initialization before being used to anonymize IP
        addresses in prefix-preserving manner.
sample.cpp  This is a sample program to illustrate the use of class
        PAnonymizer. The program reads in an example trace file
        "sample_trace_raw.dat", anonymizes the IP addresses in the
        trace file, and output the sanitized trace file to the
        standard out. You can redirect the output to a file if you
        like. The key in the file are settable.
sample_trace_raw.dat    This is an example raw trace file. Each line of the
        trace is in the format of "time  packetsize  a.b.c.d", where
        "a.b.c.d" is IP address. The sanitized trace has the same
        format, preserving everything except the IP addresses, which
        are anonymized.
sample_trace_anonymized.dat  This is the output when running the sample
        program upon "sample_trace_raw.dat".
Makefile    The makefile to generate "sample", the executable of
        sample.cpp.


3. Compile and run the sample program

To compile the sample program "sample.cpp", run

make all

To run the sample program, run

sample sample_trace_raw.dat

The sanitized version of "sample_trace_raw.dat" is wrote to standard output.
You can redirect the output to a file and compare it with file
"sample_trace_anonymized.dat". They should be the same.


4. Tailor the sample program for you own needs.

To sanitize your own traces, you need to change file "sample.cpp" to reflect
your trace formats. You also need to provide your own 256-bit key in the
program when creating an instance of class PAnonymizer.


5. Contact

Please contact Jinliang Fan(jlfan@cc.gatech.edu) if you have questions about
the programs. Your comments are highly appreciated.
