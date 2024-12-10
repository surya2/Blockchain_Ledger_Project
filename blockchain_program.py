from datetime import datetime
import hashlib
import binascii
import os

import rsa
import sys


funder = str(input())
time_format = "%a %b %d %H:%M:%S %Z %Y"

def hashFile(filename):
    hash = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda: f.read(128 * 1024), b''):
            hash.update(b)
    return hash.hexdigest()


def hashString(string):
    h = hashlib.sha256(string)
    hash_str = h.hexdigest()
    return hash_str


# given an array of bytes, return a hex reprenstation of it
def bytesToString(data):
    return binascii.hexlify(data)


# given a hex reprensetation, convert it to an array of bytes
def stringToBytes(hexstr):
    return binascii.a2b_hex(hexstr)


# Load the wallet keys from a filename
def loadWallet(filename):
    with open(filename, mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    return pubkey, privkey


# save the wallet to a file
def saveWallet(pubkey, privkey, filename):
    # Save the keys to a key format (outputs bytes)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    privkeyBytes = privkey.save_pkcs1(format='PEM')
    # Convert those bytes to strings to write to a file (gibberish, but a string...)
    pubkeyString = pubkeyBytes.decode('ascii')
    privkeyString = privkeyBytes.decode('ascii')
    # Write both keys to the wallet file
    with open(filename, 'w') as file:
        file.write(pubkeyString)
        file.write(privkeyString)
    return pubkeyBytes, privkeyBytes


def generateWallet(filename):
    public_key, private_key = rsa.newkeys(1024, poolsize=8)
    pubkeyBytes, privkeyBytes = saveWallet(public_key, private_key, filename)
    tag = hashlib.sha256(public_key.save_pkcs1(format='PEM')).hexdigest()
    wallet_tag = tag[:16]
    #wallet_tag = hash_str[:16]
    print("New wallet generated in '{0}' with tag {1}".format(filename, wallet_tag))


def createGenesis(file_name):
    file = open(file_name, "w+")
    file.write("We live in a beautiful world\r\n")
    print("Genesis block created in 'block_0.txt'")
    with open('./mempool/mempool.txt', 'w') as fp:
        pass


def getTagFromPubkey(pubkeyBytes):
    hash_str = hashlib.sha256(pubkeyBytes.save_pkcs1(format='PEM')).hexdigest()
    #hash_str = hashString(bytesToString(pubkeyBytes).decode('ascii'))
    tag = hash_str[:16]
    return tag


def processFunding(fund_file, tag_a, amount_to_fund):
    time_of_funding = str(datetime.now().strftime(time_format))
    with open(fund_file, 'w') as file:
        file.write(f"{funder} transferred {amount_to_fund} to {tag_a} on {time_of_funding}")
    print(f"Funded wallet {tag_a} with {amount_to_fund} SurjaCoins on {time_of_funding}")


def processTransfer(transfer_file, src_wallet, dest_tag, amount_to_transfer):
    pubkeyBytes, privkeyBytes = loadWallet(src_wallet)
    src_tag = getTagFromPubkey(pubkeyBytes)
    time_of_transfer = str(datetime.now().strftime(time_format))
    transaction_line = f"{src_tag} transferred {amount_to_transfer} to {dest_tag} on {time_of_transfer}"
    signature = rsa.sign(transaction_line.encode(), privkeyBytes, 'SHA-256')
    signed_hash = bytesToString(signature).decode()
    with open(transfer_file, 'w') as file:
        file.write(f"{transaction_line}\n")
        file.write(f"{signed_hash}")
    print(
        f"Transferred {amount_to_transfer} from {src_wallet} to {dest_tag} and the statement to '{transfer_file}' on {time_of_transfer}")

def getBalance(acct_tag):
    mempool = open('./mempool/mempool.txt', 'r')
    total_balance = 0
    for line in mempool.read().splitlines():
        line_parts = line.split(" ")
        sender = line_parts[0]
        reciever = line_parts[4]
        amount = line_parts[2]
        if sender == acct_tag and amount is not None:
            #acct is losing money
            total_balance -= int(line_parts[2])
        if reciever == acct_tag and amount is not None:
            #acct is gains money
            total_balance += int(line_parts[2])

    block_num = 1
    while os.path.isfile('./transaction_blocks/block_{0}.txt'.format(str(block_num))):
        with open('./transaction_blocks/block_{0}.txt'.format(str(block_num))) as file:
            for line in file.readlines():
                line_parts = line.split(" ")
                if len(line_parts) >= 5:
                    if line_parts[0] == acct_tag and line_parts[2] is not None:
                        # acct is losing money
                        total_balance -= int(line_parts[2])
                    if line_parts[4] == acct_tag and line_parts[2] is not None:
                        # acct is gaining money
                        total_balance += int(line_parts[2])
        block_num += 1
    return total_balance

def enoughFunds(src_tag, amount_to_transfer):
    print(src_tag)
    src_balance = getBalance(src_tag)
    print(src_balance)
    print(amount_to_transfer)
    return src_balance >= int(amount_to_transfer)

def validSignature(pubkeyBytes, signed_hash, transaction_line):
    signature = stringToBytes(signed_hash.encode())
    #signed_hash = rsa.sign(transaction_line.encode(), privkeyBytes, 'SHA-256').hex()
    try:
        rsa.verify(transaction_line.encode(), signature, pubkeyBytes)
    except rsa.VerificationError:
        return False
    return True

def processVerification(src_wallet, transfer_file):
    mempool = open("./mempool/mempool.txt", 'a')
    pubkeyBytes, privkeyBytes = loadWallet(src_wallet)
    tag = getTagFromPubkey(pubkeyBytes)

    with open(transfer_file) as file:
        lines = file.read().splitlines()
    transaction_line = lines[0]
    statement_parts = transaction_line.split(" ")
    if statement_parts[0] == funder:
        mempool.write(transaction_line+"\n")
        print("Any funding request (i.e., from SurjaBoy) is considered valid; written to the mempool")
    else:
        if enoughFunds(statement_parts[0], statement_parts[2]) and validSignature(pubkeyBytes, lines[1], transaction_line):
            mempool.write(transaction_line+"\n")
            print(f"The transaction in file '{transfer_file}' with wallet '{src_wallet}' is valid, and was written to the mempool")
        else:
            print(
                f"The transaction in file '{transfer_file}' with wallet '{src_wallet}' is NOT valid, and was NOT written to the mempool")

def mine(leading_zeros):
    num_files = 0
    ordered_dirctory = sorted(os.listdir())
    for file in ordered_dirctory:
        if file.split('_')[0] == 'block':
            num_files += 1

    prev_filename = './transaction_blocks/block_{0}.txt'.format(str(num_files-1))
    file_hash = hashFile(prev_filename)

    mempool = open('./mempool/mempool.txt', 'r')
    mempool_lines = mempool.read().splitlines()

    new_block = './transaction_blocks/block_{0}.txt'.format(str(num_files))
    with open(new_block, 'a') as file:
        file.write(f"{file_hash}\n\n")
        for line in mempool_lines:
            file.write(line+"\n")
        file.write("\nnonce: {0}".format('0'))
    mempool.close()
    open('./mempool/mempool.txt', 'w').close()

    cur_hash = hashFile('./transaction_blocks/block_{0}.txt'.format(str(num_files)))
    difficulty = cur_hash[:leading_zeros].count('0')
    nonce = 0
    while difficulty != leading_zeros:
        with open(new_block, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        lines[-1] = "nonce: {0}".format(str(nonce))
        with open(new_block, 'w', encoding='utf-8') as file:
            file.writelines(lines)
        cur_hash = hashFile('./transaction_blocks/block_{0}.txt'.format(str(num_files)))
        difficulty = cur_hash[0:leading_zeros].count('0')
        nonce += 1
    #cur_hash = hashFile('block_{0}.txt'.format(str(num_files)))
    print(f"Mempool transactions moved to {new_block} and mined with difficulty {difficulty} and nonce {nonce}")


def validate():
    if not os.path.isfile("./transaction_blocks/block_0.txt"):
        return False
    else:
        block = 1
        while os.path.isfile('./transaction_blocks/block_{0}.txt'.format(str(block))):
            cur_prevHash = hashFile('./transaction_blocks/block_{0}.txt'.format(str(block - 1)))
            with open('./transaction_blocks/block_{0}.txt'.format(str(block))) as file:
                lines = file.read().splitlines()
                actual_prevHash = lines[0]
            if cur_prevHash != actual_prevHash:
                return False
            block += 1
        return True

def process(arg, index):
    arg_lower = arg.lower().strip('-')
    if arg_lower == 'name':
        print("SurjaCoin (TM)")
    elif arg_lower == "genesis":
        file_name = "./transaction_blocks/block_0.txt"
        createGenesis(file_name)
    elif arg_lower == 'generate':
        index += 1
        file_name = sys.argv[index]
        generateWallet(file_name)
    elif arg_lower == 'address':
        index += 1
        file_name = sys.argv[index]
        pubkeyBytes, privkeyBytes = loadWallet(file_name)
        print(getTagFromPubkey(pubkeyBytes))
    elif arg_lower == 'fund':
        tag_a = sys.argv[index + 1]
        amount_to_fund = sys.argv[index + 2]
        fund_file = sys.argv[index + 3]
        index += 3
        processFunding(fund_file, tag_a, amount_to_fund)
    elif arg_lower == "transfer":
        src_wallet = sys.argv[index + 1]
        dest_tag = sys.argv[index + 2]
        amount_to_transfer = sys.argv[index + 3]
        transfer_file = sys.argv[index + 4]
        processTransfer(transfer_file, src_wallet, dest_tag, amount_to_transfer)
    elif arg_lower == 'balance':
        index += 1
        acct_tag = sys.argv[index]
        balance = getBalance(acct_tag)
        print(balance)
    elif arg_lower == 'verify':
        src_wallet = sys.argv[index+1]
        transfer_file = sys.argv[index+2]
        index += 2
        processVerification(src_wallet, transfer_file)
    elif arg_lower == "mine":
        index+=1
        leading_zeros = int(sys.argv[index])
        mine(leading_zeros)
    elif arg_lower == "validate":
        isValid = validate()
        print(isValid)

    return index


n = len(sys.argv)
i = 1
while i < n:
    i = process(sys.argv[i], i)
    i += 1
