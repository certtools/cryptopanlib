CXX=g++
CC=gcc
CFLAGS=-O4 -Wall -Wno-strict-aliasing -fpermissive -fPIC -shared
CFLAGS=-O4 -Wno-strict-aliasing -fPIC -shared
FLAGS=$(CFLAGS)

# TARGET=logfile-panonymizer 
TARGET=cryptopanlib.so 

OBJS = crypto.o panonymizer.o sample.o  

.SUFFIXES: .cpp

all: $(TARGET) 



cryptopanlib.so:	cryptopanlib.cpp crypto.o panonymizer.o
	$(CXX) $(FLAGS) -Wl,-soname,cryptopalib -fPIC -shared -o cryptopanlib.so cryptopanlib.cpp crypto.o panonymizer.o -lssl


#$(TARGET): $(OBJS) 
#	$(CXX) $(FLAGS) $(OBJS) -o $@ -lcrypto

.cpp.o: 
	$(CXX) -c $(CFLAGS) $< 

clean: 
	rm -f $(OBJS) $(TARGET) 
