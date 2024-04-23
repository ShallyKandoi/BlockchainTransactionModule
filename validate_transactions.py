import hashlib
import ecdsa

from p2pkh import validate_signature,parse_locking_script,parse_unlocking_script,validate_script,create_unlocking_script,create_locking_script,generate_public_key_hash

class Transaction:
    def __init__(self, sender_public_key, receiver_public_key_hash, amount,locking_script,unlocking_script):
        self.sender_public_key = sender_public_key
        self.receiver_public_key_hash = receiver_public_key_hash
        self.amount = amount
        self.message = b"Hello, world!"
        self.locking_script=locking_script
        self.unlocking_script=unlocking_script
        self.signature = None  # Placeholder for the signature, will be set during signing
        #self.id = self.calculate_hash()  # Generate a unique ID for the transaction

    #def calculate_hash(self):
    #    hash_string = self.sender_public_key + self.receiver_public_key_hash + str(self.amount)
    #    return hashlib.sha256(hash_string.encode()).hexdigest()

    def sign_transaction(self, private_key):
        # Implement signing logic using the private key
        pass

    def is_valid(self, state, valid_transactions):
        sender_balance = state.get(self.sender_public_key, 0)
        total_amount = self.amount
        for transaction in valid_transactions:
            if transaction.sender_public_key == self.sender_public_key:
                total_amount += transaction.amount
        valid=validate_script(self.locking_script,self.unlocking_script,self.message)
        if sender_balance < total_amount or not valid:
            return False
        return True



class TransactionPool:
    def __init__(self):
        self.transactions = []

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    def validate_transactions(self, state):
        valid_transactions = []
        for transaction in self.transactions:
            if transaction.is_valid(state,valid_transactions):
                valid_transactions.append(transaction)
        return valid_transactions

# Usage example:
initial_state_of_economy = {
    "sender_public_key": 200,
    "receiver_public_key_hash": "hash_of_receiver_public_key",
}

def generate_public_key_hash(public_key):
    # Step 2: Hash the public key (SHA-256 followed by RIPEMD-160)
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash


# Generate a private key
receiver_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

# Get the corresponding public key
receiver_public_key = receiver_private_key.verifying_key.to_string()

# Create a message to sign
message = b"Hello, world!"

# Sign the message
receiver_signature = receiver_private_key.sign(message)

receiver_public_key_hash= generate_public_key_hash(receiver_public_key)

# Create a transaction
sender_public_key = "sender_public_key"
amount = 100
locking_script=create_locking_script(receiver_public_key_hash)
unlocking_script=create_unlocking_script(receiver_signature,receiver_public_key)
transaction1 = Transaction(sender_public_key, receiver_public_key_hash, amount,locking_script,unlocking_script)
transaction2 = Transaction(sender_public_key, receiver_public_key_hash, amount,locking_script,unlocking_script)
transaction3 = Transaction(sender_public_key, receiver_public_key_hash, amount,locking_script,unlocking_script)

# Add the transaction to the transaction pool
transaction_pool = TransactionPool()
transaction_pool.add_transaction(transaction1)
transaction_pool.add_transaction(transaction2)
transaction_pool.add_transaction(transaction3)

# Validate transactions against the current state of the economy
valid_transactions = transaction_pool.validate_transactions(initial_state_of_economy)

print(len(valid_transactions))