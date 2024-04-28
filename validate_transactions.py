from p2pkh import validate_signature,parse_locking_script,parse_unlocking_script,validate_script,create_unlocking_script,create_locking_script,generate_public_key_hash
#importing various helper functions from p2pkh.py
from user import User
#importing user class

class Transaction:
    def __init__(self, sender, receiver,amount):
        self.sender = sender #Placeholder to store sender object of class User
        self.receiver = receiver #Placeholder to store receiver object of class User
        self.amount = amount #Placeholder for amount
        self.message = b"Hello, world!" #Placeholder to store message used for signing
        self.locking_script=create_locking_script(generate_public_key_hash(str(receiver.get_public_key()))) #Creating locking script for the current transaction

    def is_valid(self, valid_transactions): #Function to validate whether a particular transaction is valid
        sender_balance = self.sender.get_money() #Storing initial balance of the sender
        total_amount = self.amount 
        flag=0 #Indicator variable to indicate if p2pkh script was called
        for transaction in valid_transactions:
            if transaction.sender == self.sender: #Taking care of valid transactions where sender has spend money
                total_amount += transaction.amount
            if transaction.receiver == self.sender: #Taking care of valid transactions where sender has received money
                flag=1
                if validate_script(transaction.locking_script,create_unlocking_script(self.sender.get_private_key().sign(self.message),self.sender.get_public_key()),self.message):
                 #Using p2pkh script to validate the locking and unlocking script
                 total_amount-=transaction.amount
        if flag:
            print("p2pkh script is called to verify money has been received earlier")
        if sender_balance < total_amount: #If the sender does not have sufficient balance
            return False
        return True

class TransactionPool:
    def __init__(self):
        self.transactions = [] #Placeholder for storing all transactions
        self.valid_transactions = [] #Placeholder for storing valid transactions

    def add_transaction(self, transaction):
        self.transactions.append(transaction) #Adding the current transaction to list of transactions
        self.validate_transactions() #Function call to validate transaction

    def validate_transactions(self):
        if self.transactions[-1].is_valid(self.valid_transactions): #Calling the is_valid() function to validate the transaction
            self.valid_transactions.append(transaction)
            print("\nTransaction is valid and added to set of valid transactions")
        else:
            print("\nTransaction is not valid")

    def get_balance(self,user): #Function to calculate the current balance of user
        amt=user.initial_money
        for transaction in self.valid_transactions: #Iterating the set of valid transactions
            if transaction.sender == user:
                amt -= transaction.amount
            if transaction.receiver == user:
                amt+=transaction.amount
        return amt


# Create different users
name1="A"
name2="B"
name3="C"
name4="D"
name5="E"

user1=User(name1,100)
user2=User(name2,30)
user3=User(name3,0)
user4=User(name4,0)
user5=User(name5,0)

#Dictionary defined to access user object with the help of name
mapping={
    name1:user1,
    name2:user2,
    name3:user3,
    name4:user4,
    name5:user5
}

#Printing the initial state of economy
print("Initial state of economy")
print(user1.name,":",user1.initial_money)
print(user2.name,":",user2.initial_money)
print(user3.name,":",user3.initial_money)
print(user4.name,":",user4.initial_money)
print(user5.name,":",user5.initial_money)

#Initialising the object of TransactionPool class
transaction_pool = TransactionPool()

while 1:
    print("\n1. Send money")
    print("2. Exit")
    user_input = int(input("Enter [1/2]: "))
    if user_input==1:
        input1,input2,amt=input("\nEnter sender,receiver,amount: ").split()
        amt=int(amt)
        transaction=Transaction(mapping[input1],mapping[input2],amt) #Creating a transaction
        transaction_pool.add_transaction(transaction)
        #Printing the current state of economy
        print("\nCurrent state of economy:")
        print(user1.name,":",transaction_pool.get_balance(user1))
        print(user2.name,":",transaction_pool.get_balance(user2))
        print(user3.name,":",transaction_pool.get_balance(user3))
        print(user4.name,":",transaction_pool.get_balance(user4))
        print(user5.name,":",transaction_pool.get_balance(user5))
    else:
        break