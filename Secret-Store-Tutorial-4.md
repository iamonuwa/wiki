---
title: Part 4 - Introducing permissioning
---

TODO

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

|[ < Part 3 (Key retrieval)](Secret-Store-Tutorial-3)|

