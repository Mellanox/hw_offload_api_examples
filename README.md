# Mellanox HW offloads examples

This is a collection of HW offload examples targeting storage applications.

## DV signature API

* signature_offload_api_example. Offloading T10-DIF, CRC32 and CRC32C calculation.
* pelining_example. An optimized way to implement the reading flow with T10-DIF offload in storage applications.

## Erasure coding API

Offloading block Reed-Solomon type erasure coding calculation.

* ec_encode_example . Local calculation.
* ec_encode_send_example . Calculate and send data to remote destination.

## Sources

```
git clone git@github.com:Mellanox/hw_offload_api_examples.git
cd hw_offload_api_examples
git submodule update --init
```
