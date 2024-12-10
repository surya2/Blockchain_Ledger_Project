import hashlib
import os
from datetime import datetime

import rsa
import binascii


def bytesToString(data):
    return binascii.hexlify(data)

def hashFile(filename):
    hash = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda: f.read(128 * 1024), b''):
            hash.update(b)
    return hash.hexdigest()
transfer_file = "transfers_requests/transfer0.txt"
(public_key, private_key) = rsa.newkeys(1024)
pubkey_bytes = public_key.save_pkcs1(format='PEM')
with open(transfer_file) as file:
    signed_hash = rsa.sign(file.read().encode(), private_key, 'SHA-256').hex()
print(signed_hash)

with open('transfers_requests/transfer0.txt') as file:
    print(file.read().splitlines())

cur_hash = "7083h000juishge784"
leading_zeros = 2
print(cur_hash[:leading_zeros])
print(cur_hash[:leading_zeros].count('0'))
#print(bytesToString(pubkey_bytes).decode())

# fund_file = "transfer0.txt"
# tag_a = 456
# amount_to_fund = 8
# time_format = "%a %b %d %H:%M:%S %Z %Y"
# with open(fund_file, 'r+') as file:
#     file.write("Account: {0}\n".format(tag_a))
#     file.write("Amount: {0}\n".format(amount_to_fund))
#     file.write("Date: {0}\n".format(str(datetime.now().strftime(time_format))))
#     print(file.read())
# with open(fund_file, 'a') as file:
#     file.write("ghui")
