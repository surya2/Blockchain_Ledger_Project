from ecdsa import SigningKey, VerifyingKey, NIST384p
import rsa
import sys
import hashlib


class Wallet_EDCSA:
    def __init__(self):
        self.private_key = SigningKey.generate(curve=NIST384p)
        self.public_key = self.private_key.verifying_key


class Wallet_RSA:
    def __init__(self):
        (self.public_key, self.private_KEY) = rsa.newkeys(2048, poolsize=8)


class Block_Node:
    def __init__(self, name, prevNode=None, hasRoot=True, this_hash=None):
        self.name = name
        self.prevNode = prevNode
        self.hasRoot = hasRoot
        self.wallet = Wallet_RSA()
        self.hash = this_hash
        # print("Node Name: " + str(name) + " | Data: " + str(data) + " |  Previous Hash: " + str(self.nextNode)[25:43])

    def get_next(self):
        return self.prevNode

    def set_next(self, data):
        self.prevNode = data

    def get_name(self):
        return self.name

    def has_next(self):
        if self.get_next() is None:
            return False
        return True

    def print(self):
        return str(
            "Node Name: " + str(self.name) + " | Data: " + str(self.data) + " | Hash: " + "  Previous Hash: " + str(
                self.prevNode)[25:43])


class Chain:
    def __init__(self):
        self.root = None
        self.name = None
        self.size = 0

    def add_genesis(self, name):
        # m = hashlib.sha3_256()
        self.name = name
        sha256 = hashlib.sha256()
        with open(name, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                sha256.update(data)
        cur_hash = sha256.hexdigest()
        new_node = Block_Node(name, hasRoot=True, this_hash=cur_hash)
        self.root = new_node

    def remove(self, d):
        this_node = self.root
        next_node = this_node.get_next

        while this_node is not None:
            if this_node.get_data() == d:
                if next_node is not None:
                    next_node.set_next(this_node.get_next())
                else:
                    self.root = this_node.get_next()
                self.size -= 1
                return True  # data removed
            else:
                next_node = this_node
                this_node = this_node.get_next()
        return False  # data not found

    def display(self):
        this_node = self.root
        if this_node is None:
            return
        print(this_node.print())
        while this_node.has_next():
            this_node = this_node.get_next()
            print(this_node.print())

    def findByName(self, name):
        this_node = self.root
        next_node = this_node.get_next()
        if this_node.get_name() == name:
            print(this_node.print())
            return
        while this_node.has_next():
            this_node = this_node.get_next()
            if this_node.get_name() == name:
                print(this_node.print())
        # if this_node.get_name() == name:

    def find(self, d):
        this_node = self.root
        next_node = this_node.get_next()
        if this_node.get_data() == d:
            print(this_node.print())
            return
        while this_node.has_next():
            this_node = this_node.get_next()
            if this_node.get_data() == d:
                print(this_node.print())

        # if this_node.get_name() == name:

    def get_size(self):
        return self.size


chain = Chain()


def process(self, arg, index):
    argv = arg.lower()
    if argv == 'name':
        print("SurjaCoin (TM)")
    elif argv == "genesis":
        file_name = "./transaction_blocks/block_0.txt"
        file = open(file_name, "w+")
        file.write("This is the Genesis block\r\n")
        chain.add_genesis(file_name)
    elif argv == 'generate':
        index += 1
        file_name = sys.argv[index]


def add(self, name):
    # m = hashlib.sha3_256()
    self.name = name
    sha256 = hashlib.sha256()
    with open(name, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256.update(data)
    cur_hash = sha256.hexdigest()
    new_node = Block_Node(name, self.root, hasRoot=True, this_hash=cur_hash)
    self.root = new_node


n = len(sys.argv)
for i in range(1, n):
    process(sys.argv[i], i)

chain.add(0, "Genesis Node")
chain.add(2, "First Node")
chain.add(3, "Next")
chain.add(6, "Root")
chain.remove(2)
# list.removeByName("Root")
chain.display()
print(" ")
chain.findByName("Next")
chain.find(6)
