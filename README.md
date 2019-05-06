# Mellanox HW offloads examples

This is a collection of HW offload examples targeting storage applications.

## Signature API

* signature_offload_api_example . Offloading T10-DIF and CRC32 calculation. Needs special MOFED build with user-space signature API.

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
