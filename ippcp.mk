ippcp_SOURCES = ippcp_provider.cc ippcp_db_bench_env.cc
ippcp_HEADERS = ippcp_provider.h
ippcp_LDFLAGS = -lippcp -u ippcp_reg -u ippcp_db_bench_env
