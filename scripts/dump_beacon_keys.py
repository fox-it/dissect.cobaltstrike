#!/usr/bin/env python3
#
# This script dumps the RSA Private Key from `.cobaltstrike.beacon_keys`.
#
# It requires the javaobj module, install it with:
#
#   $ pip install javaobj-py3
#
import javaobj
import base64

key = javaobj.loads(open(".cobaltstrike.beacon_keys", "rb").read())
privkey_der = bytes(c & 0xFF for c in key.array.value.privateKey.encoded)

print("-----BEGIN RSA PRIVATE KEY-----")
print(base64.encodebytes(privkey_der).strip().decode())
print("-----END RSA PRIVATE KEY-----")
