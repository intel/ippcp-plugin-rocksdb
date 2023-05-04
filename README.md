# Intel® Integrated Performance Primitives Cryptography Plugin for RocksDB* Storage Engine

`ippcp` is an encryption provider for RocksDB that is based on Intel's Integrated Performance Primitives for Cryptography (IPPCP). IPPCP is a lightweight cryptography library that is highly optimized for various Intel CPUs. It's used here to provide AES-128/192/256 encryption, with a CTR mode of operation, for RocksDB.

## Prerequisite

There is a dependency on ipp cryptograhy library (ippcp) which needs to be installed. Please refer below link for installtion.
https://www.intel.com/content/www/us/en/develop/documentation/get-started-with-ipp-crypto-for-oneapi-linux/top.html

Once Installed source /opt/intel/oneapi/ippcp/latest/env/var.sh


## Build

The code first needs to be linked under RocksDB's "plugin/" directory. In your RocksDB directory, run:

```
$ pushd ./plugin/
$ git clone https://github.com/intel/ippcp-plugin-rocksdb.git ippcp
```

Next, we can build and install RocksDB with this plugin as follows:

```
$ popd
$ make clean && ROCKSDB_PLUGINS=ippcp make -j48 release
```

## Testing

* Install ipp cryptograhy library (ippcp) as described in the previous section.
* Install  https://github.com/google/googletest
* Build RocksDB as a shared library

```
LIB_MODE=shared make -j release

```

* Go to the tests directory of ippcp plugin and build as mentioned below:

```
cd plugin/ippcp/tests/
mkdir build
cd build
cmake -DROCKSDB_PATH=<rocksdb_install_directory> -DIPPCRYPTOROOT=<ippcp_install_directory> ..
make run

```
## Tool usage

For RocksDB binaries (such as the `db_bench` we built above), the plugin can be enabled through configuration. `db_bench` in particular takes a `--fs_uri` where we can specify "dedupfs" , which is the name registered by this plugin. Example usage:

```
$ ./db_bench --benchmarks=fillseq --env_uri=ippcp_db_bench_env --compression_type=none
```

## Application usage

The plugin's interface is also exposed to applications, which can enable it either through configuration or through code. Example available under the "examples/" directory.

```