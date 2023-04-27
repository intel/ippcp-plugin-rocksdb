include ../../../make_config.mk

PLATFORM_LDFLAGS += -lippcp -u ippcp_reg

.PHONY: clean

all: ippcp_example

ippcp_example: ippcp_example.cc
	$(CXX) $(CXXFLAGS) $@.cc -o$@ ../../../librocksdb.a -I../../../include -O2 -std=c++11 $(PLATFORM_LDFLAGS) $(PLATFORM_CXXFLAGS) 

clean:
	rm -rf ./ippcp_example
