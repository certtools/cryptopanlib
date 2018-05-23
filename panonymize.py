#!/usr/bin/env python3

# Copyright 2018 by L. Aaron Kaplan <kaplan@cert.at>, all rights reserved

import sys
import time
import random
import ipaddress
from ctypes import cdll, c_uint

try:
    panonymize_lib = cdll.LoadLibrary("cryptopanlib.so")
except Exception as e:
    print("could not load cryptopanlib.so")
    sys.exit(-1)
else:
    print("loaded cryptopanlib @ %s" % panonymize_lib)


panonymize_lib.init(b"12345678901234567890123456789012")
anonymize = panonymize_lib.anonymize_str
#anonymize = panonymize_lib.anonymize_str
anonymize.restype = c_uint

N = 10**1


start = time.time()

for i in range(0, N):
    # ip_str = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    ip_str = "24.5.0.80"
    ip = ipaddress.ip_address(ip_str)
    print("ip addr: %s" % ip)
    p = anonymize(ip_str.encode('utf-8'))
    print("anonymized to %s" % ipaddress.ip_address(p))

print()
stop = time.time()
duration = stop - start
print("encrypted {} ints in {} seconds. rate = {}".format(N, duration, N / duration))
