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

1. Client sends IO request to server. The IO request can be "read" or "write" operation. User data can be inlined in the IO request or transffered using RDMA
2. Based on requst type. Server reads data from the client side ("write" request), or writes data to the client side ("read" request)
3. IO request contains variable-length data paylod. But server stores the data in fixed-size chinks. Each chunk in addtion to user data includes a metadata calculated in servers side
4. At the end of each transaction, server sends to clietn a completion

From network perspective, each IO request involves following operations:

1. Client -> Server. Send request
2. If data is not inlined in IO request. Server -> Client.  RDMA Read/Write operation
3. Server -> Client. Send responce

### Message format

IO request includes:
- Header
- Payload
- Tail

#### Header

Field | Size     | Description 
------| ---------|-------------
ID    | uint64_t | Unique ID of IO request
Size  | uint16_t | Size of user data
Type  | uint8_t  | Type of the request: 0 - read, 1 - write

#### Payload

Payload is array of bytes in lenght of Header.Size

### Tail

Field      | Size     | Description 
-----------| ---------|-------------
Signature  | uint32_t | CRC32 signature that protects user data

