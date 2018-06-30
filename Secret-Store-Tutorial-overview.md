---
title: Secret Store Tutorial Overview
---

In this tutorial, we will learn step by step how to setup a Secret Store with 3 nodes and use it for a simple use case:

Alice has a confidential document stored locally on her hard-drive. She would like to encrypt it, store the encryption key in a secure way and eventually share the document later on.
Alice decides to share this encrypted document with Bob and Bob only.

To keep things simple we will work on a [Private development chain](Private-development-chain) but the Secret Store nodes are meant to be connected to and synchronize any blockchain (Private or Public).

The overall picture of this tutorial is the following:
- 3 Secret Store nodes (each with an account)
- 3 regular user accounts (Alice, Bob and Charlie)
![system overview](images/ss-overview-0.jpg)
- Each entity on this picture is running a node on the same blockchain. Interactions with the blockchain are not represented on this diagram.
- The nodes part of the secret store are connected with each other using a secure connection (blue lines).
- The Secret Store node 1 (SS1) has an HTTP interface open to the word that Alice, Bob and Charlie will use (orange lines).
- Alice will send an encrypted document to Bob per email (gray line).


The tutorial is partitioned in the following steps:
- [Configuring each node](Secret-Store-Tutorial-1.md)
-- [Build Parity with the Secret Store feature]
-- [Create and configure the users nodes]
-- [Create and configure the Secret Store nodes]



[Next Step (Configuring each node) > ](Secret-Store-Tutorial-1)



2 accounts: Alice and Bob
 Alice has a document, encrypts it with a specific key given by the SS, transmit the encrypted document offline.


Alice: alicepwd
0xe5a4b6f39b4c3e7203ca8caeecbad58d8f29b046

Bob: bobpwd
0xfeacd0d28fd158ba2d3adb6d69d20c723214edc9

Charlie: charliepwd
0xdab0055e3abb40d7281b058bb5e6966c50582951



#### 4. Store the key on the SS
Run  `Document key storing session`  with (`common_point`,  `encrypted_point`) pair && thus stores the key on SS

```bash
curl -X POST http://localhost:8082/shadow/f14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c/f1dd9ce1379046cb186b97e0ed257779d48442b1de68152a7a33189ab727dd7663faf97f367b05837d9045c7aae0922cc70f9f7f75d30cf9c1ded37635ea4d3b01/8ef3b2ae741ec6903bb11878b545b08fdc288f32eadab5d2ac33e6c334b40c9b5a687224ca6dd7831bde118fd3e6fed95fd90d5a76b46a858ed46f54d58eaaaa/b7ad0603946987f1a154ae7f074e45da224eaa83704aac16a2d43a675d219654cf087b5d7aacce0790a65abbc1a495b26e71a5c6e9a4a71b543bf0048935bc13
```

Here:

-   `http://localhost:8082`: is the address on which node is listening for incoming requests;
-   `f14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c`: is the hex-encoded server key id (sha3 of mySecretDocument from step 1);
-   `f1dd9ce1379046cb186b97e0ed257779d48442b1de68152a7a33189ab727dd7663faf97f367b05837d9045c7aae0922cc70f9f7f75d30cf9c1ded37635ea4d3b01`: is the signed server key id from step 1.1;
-   `8ef3b2ae741ec6903bb11878b545b08fdc288f32eadab5d2ac33e6c334b40c9b5a687224ca6dd7831bde118fd3e6fed95fd90d5a76b46a858ed46f54d58eaaaa`: is the `common point` portion of encrypted document key received at step 2;
-   `f03c6dfe5bb74269d2edfc69e8e939e6615bab4681659233679a6f8ba121e10a48ed2a444ea9693bb9d546ed55bf958ce6a9d6c23d68c11fc08a3c9a566e253f`: is the `encrypted point` portion of encrypted document key received at step 2.

All SS servers should show something like:
`2018-06-27 14:03:34  0x83a0…75b4: encryption session completed`

#### 5.  Bob is given access to the document key (Permissionning)
Someday she decides to give Bob an access to the document && uses permissioning contract for this and send the encrypted document.

#### 6. Bob wants to decrypt the document

##### 6.1 Bob needs to sign the Server key (Sha3 of the document)
```bash
curl --data-binary '{"jsonrpc": "2.0", "method": "secretstore_signRawHash", "params": ["0xfeacd0d28fd158ba2d3adb6d69d20c723214edc9", "bobpwd", "0xf14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c"], "id":1 }' -H 'content-type: application/json' http://127.0.0.1:8565/ | jq
```
```json
{
  "jsonrpc": "2.0",
  "result": "0xa4e2d4d99aa3995bf2c69e421a7fab3ac7c72de7c608a93f7227228beccef45149a94cf99da17d878e87f492cd844347f368ec67faadbfdd8a17939e221d23ff01",
  "id": 1
}
```

 #####  6.2 Bob runs  `Document key shadow retrieval session`  and receives the triple (`decrypted_secret`,  `common_point`,  `decrypt_shadows`)

```bash
curl http://localhost:8082/shadow/f14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c/a4e2d4d99aa3995bf2c69e421a7fab3ac7c72de7c608a93f7227228beccef45149a94cf99da17d878e87f492cd844347f368ec67faadbfdd8a17939e221d23ff01 | jq
```
```json
{
  "decrypted_secret": "0xf73d0a117174fe2e6d60ecb7cc2f7df88261c023a671926e7924889cc2b8c74d7058882eb8577451ba9cd72021a1220f08baf9f371ef95aee1b790cfdc126da0",
  "common_point": "0x8ef3b2ae741ec6903bb11878b545b08fdc288f32eadab5d2ac33e6c334b40c9ba5978ddb3592287ce421ee702c190126a026f2a5894b957a712b90aa2a715185",
  "decrypt_shadows": [
    "0x04ec961559cc7c3e24cef8205e8649e65b14ea6e761cf31a8ea141a46654b1180edf79353602bde828b7b3f4833dfc5a68d4b6a45d081004d60ed8ab83f976660e657c16742f1414b2a88c0010eeabea09c10f40c489a1373c20eedafbf0dd342d6a2d99b7e7f6db2cb2c1aeae7ec456e74e2cda86b83773c409e80d92a8bd4c0c2e4e02513605ecdec30becf39b24c512",
    "0x044af237548b073033feb6798a8e8e4b4cfd4a668d1f740afd188c2e780c336cc5f5a13d38342e1bb4cb6a1158b999855a9aa21dc232156569ea96a47ac798ee80083883b6e14f60f1515c49c1830864e24408cb184fdda36994f2c031490f75e29c8892d15fe123feefe0d44efe01a15a4979021d57b489233be458a1f3826974d69786c82547a5b1694d779acc1697c7"
  ]
}
```

Here:

-  `http://localhost:8082`: is the address on which node is listening for incoming requests;
-  `f14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c`: is the hex-encoded server key id (sha3 of mySecretDocument from step 1);
-  `a4e2d4d99aa3995bf2c69e421a7fab3ac7c72de7c608a93f7227228beccef45149a94cf99da17d878e87f492cd844347f368ec67faadbfdd8a17939e221d23ff01` : is the hex-encoded signed server key id from 6.1.

Nodes show (error can be ignored): 
 ```
    2018-06-27 14:14:30  0x83a0…75b4: version negotiation session completed
    2018-06-27 14:14:30  0x83a0…75b4: version negotiation session read error 'no active session with given id' when requested for session from node 0x32be…8f4a
    2018-06-27 14:14:30  0x83a0…75b4: decryption session completed
    2018-06-27 14:14:30  0x83a0…75b4: decryption session read error 'no active session with given id' when requested for session from node 0x32be…8f4a
```

Shutting down 1 node.. it works!
Shutting down 2 nodes gives `Consensus unreachable` because we got a Threshold of 1 with 3 nodes, so 2 out of 3 are needed

#### 7.  Retrieve the document
Bob needs to use the triple in the  [`secretstore_shadowDecrypt`](https://wiki.parity.io/JSONRPC-secretstore-module#secretstore_shadowdecrypt)  call to get plain contents of the document

```bash
$ curl --data-binary '{"jsonrpc": "2.0", "method": "secretstore_shadowDecrypt", "params": ["0xfeacd0d28fd158ba2d3adb6d69d20c723214edc9", "bobpwd", "0xf73d0a117174fe2e6d60ecb7cc2f7df88261c023a671926e7924889cc2b8c74d7058882eb8577451ba9cd72021a1220f08baf9f371ef95aee1b790cfdc126da0", "0x8ef3b2ae741ec6903bb11878b545b08fdc288f32eadab5d2ac33e6c334b40c9ba5978ddb3592287ce421ee702c190126a026f2a5894b957a712b90aa2a715185", ["0x04ec961559cc7c3e24cef8205e8649e65b14ea6e761cf31a8ea141a46654b1180edf79353602bde828b7b3f4833dfc5a68d4b6a45d081004d60ed8ab83f976660e657c16742f1414b2a88c0010eeabea09c10f40c489a1373c20eedafbf0dd342d6a2d99b7e7f6db2cb2c1aeae7ec456e74e2cda86b83773c409e80d92a8bd4c0c2e4e02513605ecdec30becf39b24c512","0x044af237548b073033feb6798a8e8e4b4cfd4a668d1f740afd188c2e780c336cc5f5a13d38342e1bb4cb6a1158b999855a9aa21dc232156569ea96a47ac798ee80083883b6e14f60f1515c49c1830864e24408cb184fdda36994f2c031490f75e29c8892d15fe123feefe0d44efe01a15a4979021d57b489233be458a1f3826974d69786c82547a5b1694d779acc1697c7"], "0x652771aa378b1c85019d99cb7818284345ad327b6019e42525c02e9ec1625f6b"], "id":1 }' -H 'content-type: application/json' http://127.0.0.1:8565/
```
```json
{
  "jsonrpc": "2.0",
  "result": "0xd61279ea93dfa7869f3b01c8798ba7ad", //HORRAY!!
  "id": 1
}

```

Here:

-   `0xfeacd0d28fd158ba2d3adb6d69d20c723214edc9`: is the address of account, which was used as requester in [document key shadow retrieval session](https://wiki.parity.io/Secret-Store.html#document-key-shadow-retrieval-session), it's Bob's address here;
-   `bobpwd`: is the password for Bob's account;
-   `0xf73d0a117174fe2e6d60ecb7cc2f7df88261c023a671926e7924889cc2b8c74d7058882eb8577451ba9cd72021a1220f08baf9f371ef95aee1b790cfdc126da0`: is the value of `decrypted_secret` field from step 6's  results;
-   `0x8ef3b2ae741ec6903bb11878b545b08fdc288f32eadab5d2ac33e6c334b40c9ba5978ddb3592287ce421ee702c190126a026f2a5894b957a712b90aa2a715185`: is the value of `common_point` field from [document key shadow retrieval session](https://wiki.parity.io/Secret-Store.html#document-key-shadow-retrieval-session) result;
-   `["0x04ec961559cc7c3e24cef8205e8649e65b14ea6e761cf31a8ea141a46654b1180edf79353602bde828b7b3f4833dfc5a68d4b6a45d081004d60ed8ab83f976660e657c16742f1414b2a88c0010eeabea09c10f40c489a1373c20eedafbf0dd342d6a2d99b7e7f6db2cb2c1aeae7ec456e74e2cda86b83773c409e80d92a8bd4c0c2e4e02513605ecdec30becf39b24c512","0x044af237548b073033feb6798a8e8e4b4cfd4a668d1f740afd188c2e780c336cc5f5a13d38342e1bb4cb6a1158b999855a9aa21dc232156569ea96a47ac798ee80083883b6e14f60f1515c49c1830864e24408cb184fdda36994f2c031490f75e29c8892d15fe123feefe0d44efe01a15a4979021d57b489233be458a1f3826974d69786c82547a5b1694d779acc1697c7"]`: is the value of `decrypt_shadows`  field from step 6's  results;
-   `0x652771aa378b1c85019d99cb7818284345ad327b6019e42525c02e9ec1625f6b`: is the encrypted document data (result of previous [`secretstore_encrypt`](https://wiki.parity.io/JSONRPC-secretstore-module#secretstore_encrypt) call) that Alice got at step 3.


Permissionning contract:
```solidity
pragma solidity ^0.4.11;

contract SSPermissions {
  bytes32 documentKeyId = 0xf14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c;
  address alice = 0xe5a4b6f39b4c3e7203ca8caeecbad58d8f29b046;
  address bob = 0xfeacd0d28fd158ba2d3adb6d69d20c723214edc9;

  /// Both Alice and Bob can access the specified document
  function checkPermissions(address user, bytes32 document) constant returns (bool) {
    if (document == documentKeyId && (user == alice || user == bob) ) return true;
    return false;
  }
}
```
- Use http://remix.ethereum.org
- Use `--jsonrpccors all` to launch ss1 and select the unlocked account
- Connect to Web3 provider http://localhost:8545
- select right account  (for ss1: 0x93f22c0fa2e4e0750669add48dd8d9dfb8af36f4)
- add to config `acl_contract = "de3f582af859b177c6178ced85a5b28ad5b39da9"` instead of "none"
- To test in remix, don't forget to add quotes "0x_document_key" and "0x_user_key"

Test with Bob:
```
$ curl http://localhost:8010/shadow/f14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c/a4e2d4d99aa3995bf2c69e421a7fab3ac7c72de7c608a93f7227228beccef45149a94cf99da17d878e87f492cd844347f368ec67faadbfdd8a17939e221d23ff01 | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   911    0   911    0     0  19670      0 --:--:-- --:--:-- --:--:-- 19804
{
  "decrypted_secret": "0x44894605a7f12fa4beabe5e094724867588f2f4663de02789bcf4103fb0a290b22f991a0e27a4aea830996df839782dd01df916ce9779b6536b7fc4380da8189",
  "common_point": "0x8ef3b2ae741ec6903bb11878b545b08fdc288f32eadab5d2ac33e6c334b40c9ba5978ddb3592287ce421ee702c190126a026f2a5894b957a712b90aa2a715185",
  "decrypt_shadows": [
    "0x0478f243db0813d61fea3e6148582c17499ffb051dafe795e14582e8d1672b4ea6ec74a7e6e5285a4d2f61944eb60426bd8010127a31e8095a7991be27cdb93c050c6eca92cb9c5bfd279bf8957de7ed20fcb6c34948f4c527220e3dd8e94e5c90f97bde313f1a5b355d60a6361e9fe6cd231d5d67c5ef89790c21295783165644bc54f7f7259eb4308abd607905fa86c0",
    "0x04c44bee02220ed2d481a614bc0fd46cd81b1e4ebcee43fdeb9bf8a50ac9d05ad6e9fe95fe3d3cd24927529dfdfe65a3277cee253334fbac2830efb8a01f7e8494fc5ea6d5a76ee6b21b4f2fbc5f0506b1bf9a2ae0a40bfc0d14bd3d25247b85095359bb8c11c986a34844822018cd74c8728837df82fbe90d5a3f847d81f35af80416020fd86b1d5671c0e4f42631edfa"
  ]
}
```


With Charlie to get the Document

```bash
curl --data-binary '{"jsonrpc": "2.0", "method": "secretstore_signRawHash", "params": ["0xdab0055e3abb40d7281b058bb5e6966c50582951", "charliepwd", "0xf14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c"], "id":1 }' -H 'content-type: application/json' http://127.0.0.1:8565/ | jq
 ```
 ```json
{
  "jsonrpc": "2.0",
  "result": "0x5823cb03ad64bd9f2c4a334e9ac71da897a8e162fcc0288669ff8c4768f0edba1c05d3236017ea1b14eb674e45b282b785468f29ae622a2d110b260fbab5748b01",
  "id": 1
}

```

With the `-i` option to curl to see the HTTP headers. It gets a 403 forbidden.
```bash
curl -i http://localhost:8010/shadow/f14c3fce70221c0694ff7c3092ec222022a4ececfe4186ce8afd156028c2196c/5823cb03ad64bd9f2c4a334e9ac71da897a8e162fcc0288669ff8c4768f0edba1c05d3236017ea1b14eb674e45b282b785468f29ae622a2d110b260fbab5748b01
HTTP/1.1 403 Forbidden
Content-Type: application/json
Transfer-Encoding: chunked
Date: Thu, 28 Jun 2018 16:06:44 GMT

"\"Consensus unreachable\""
```

