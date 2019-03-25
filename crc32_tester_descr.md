CRC32 and UMR example
---------------------

## Overview

This example demostrates how to use CRC32 offload and zero-copy in simple storage protocol.

### Terminology

UMR is a mechanism to alter the address translation properties of MKeys by posting Work
Requests on SQs.

UMR argument can contain, in addition to the buffers description list (aka scatter/gather entries
or KLM), control blocks that extend memory management flexibility beyond banal address translation. "Strided Repeated Block"  allows to interleave elements of multiple arrays into a single cohesive array with a single command.

### UMR Programming Model

The following is a common programming procedure for a UMR:

- Create memory key with indirect or direct property, allocating enough translation space for this key
- In the critical data path:
  - Post a UMR Work Request on the SQ that is destined to use the new mapping. (MKey should be at a valid and free state).
  - Post a WQE that uses the newly mapped MKey through local or remote access
   - Optionally, upon completion of the operation, invalidate the MKey in the HCA by posting an additional UMR which sets the free bit, or using send with invalidate command from remote node
   
## Storage protocol overview

The example implements a simple storrage protocol between a client (host) and server (target). 

1. Client sends IO request to server
1
