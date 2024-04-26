import hashlib
import ecdsa

from p2pkh import validate_signature,parse_locking_script,parse_unlocking_script,validate_script,create_unlocking_script,create_locking_script,generate_public_key_hash
from user import User

class Transaction:
    def __init__(self, sender, receiver,amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.message = b"Hello, world!"
        self.locking_script=create_locking_script(generate_public_key_hash(str(receiver.get_public_key())))
        self.signature = None  # Placeholder for the signature, will be set during signing
        #self.id = self.calculate_hash()  # Generate a unique ID for the transaction

    #def calculate_hash(self):
    #    hash_string = self.sender_public_key + self.receiver_public_key_hash + str(self.amount)
    #    return hashlib.sha256(hash_string.encode()).hexdigest()

    def sign_transaction(self, private_key):
        # Implement signing logic using the private key
        pass

    def is_valid(self, valid_transactions):
        sender_balance = self.sender.get_money()
        total_amount = self.amount
        flag=0
        for transaction in valid_transactions:
            if transaction.sender == self.sender:
                total_amount += transaction.amount
            if transaction.receiver == self.sender:
                flag=1
                if validate_script(transaction.locking_script,create_unlocking_script(self.sender.get_private_key().sign(self.message),self.sender.get_public_key()),self.message):
                 total_amount-=transaction.amount
        if flag:
            print("p2pkh script is called to verify money has been received earlier")
        if sender_balance < total_amount:
            return False
        return True

class TransactionPool:
    def __init__(self):
        self.transactions = []
        self.valid_transactions = []

    def add_transaction(self, transaction):
        self.transactions.append(transaction)
        self.validate_transactions()

    def validate_transactions(self):
        if self.transactions[-1].is_valid(self.valid_transactions):
            self.valid_transactions.append(transaction)
            print("\nTransaction is valid and added to set of valid transactions")
        else:
            print("\nTransaction is not valid")

    def get_balance(self,user):
        amt=user.initial_money
        for transaction in self.valid_transactions:
            if transaction.sender == user:
                amt -= transaction.amount
            if transaction.receiver == user:
                amt+=transaction.amount
        return amt


# Create a transaction
name1="SHALLY"
name2="SHIVAM"
name3="PAKHARIYA"
name4="RAJ"
name5="ROHIT"

user1=User(name1,100)
user2=User(name2,30)
user3=User(name3,0)
user4=User(name4,0)
user5=User(name5,0)

mapping={
    name1:user1,
    name2:user2,
    name3:user3,
    name4:user4,
    name5:user5
}

print("Initial state of economy")
print(user1.name,":",user1.initial_money)
print(user2.name,":",user2.initial_money)
print(user3.name,":",user3.initial_money)
print(user4.name,":",user4.initial_money)
print(user5.name,":",user5.initial_money)

transaction_pool = TransactionPool()

while 1:
    print("\n1. Send money")
    print("2. Exit")
    user_input = int(input("Enter [1/2]: "))
    if user_input==1:
        input1,input2,amt=input("\nEnter sender,receiver,amount: ").split()
        amt=int(amt)
        transaction=Transaction(mapping[input1],mapping[input2],amt)
        transaction_pool.add_transaction(transaction)
        print("\nCurrent state of economy:")
        print(user1.name,":",transaction_pool.get_balance(user1))
        print(user2.name,":",transaction_pool.get_balance(user2))
        print(user3.name,":",transaction_pool.get_balance(user3))
        print(user4.name,":",transaction_pool.get_balance(user4))
        print(user5.name,":",transaction_pool.get_balance(user5))
    else:
        break