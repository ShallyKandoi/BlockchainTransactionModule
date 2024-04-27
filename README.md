### Overview

Our project encompasses essential aspects of blockchain transaction processing. It includes the implementation of transaction scripts like P2PK, P2PKH, and P2MS, which facilitate various transaction types within the blockchain network. Additionally, we have a hash function to bolster security measures, ensuring the integrity of transactions and data, which is used in P2PKH scripts. Furthermore, our project incorporates user and transaction classes for simulating transactions, providing a practical environment for testing and validating the functionality of the implemented scripts and hashing techniques. This comprehensive approach establishes a solid foundation for building and evaluating blockchain systems, emphasizing security, efficiency, and flexibility in transaction processing.

### Bitcoin Scripts

A Script program consists of two types of objects:

-   OP_CODES: These are specific bytes representing certain operations, like Addition, Subtraction, Multiplication, etc.
-   DATA: Everything that is not an OP_CODE is interpreted as raw data and pushed onto the stack.

In all the 3 scripts, the following things should be taken into account:

-   The transactions are simply assumed to be a message like `b"Hello, world!"`.
-   ECDSA (Elliptic Curve Digital Signature Algorithm) library is used for the creation of public-private key pairs, signing of the message using the private key, and validation of digital signatures.

1.  Pay-to-Public-Key (P2PK)

    -   ScriptSig is the unlocking script, and ScriptPubkey is the locking script.
    -   How to run the file: `python p2pk.py`
2.  Pay-to-Public-Key-Hash (P2PKH)

    -   ScriptSig is the unlocking script, and ScriptPubkey is the locking script.
    -   How to run the file: `python p2pkh.py`
3.  Pay-to-Multisig (P2MS)

    -   ScriptSig is the unlocking script, and ScriptPubkey is the locking script.
    -   How to run the file: `python p2ms.py`

### Transaction Simulation

-   Predefined users are created. A `user.py` file is used to create a user object containing the initial balance, public key, and private key for every user.
-   Users are asked to select the sender, receiver, and amount.
-   Upon selection, a transaction instance is created and added to the list of transactions.
-   To validate the transactions, we check whether the sender has the required amount of money by iterating through the list of valid_transactions and updating the amount spent and received.
-   To use the amount received in any previous transaction, we call the validate script function, which passes the locking script and unlocking script. Here we have considered the scripts to be of the format P2PKH.
-   Once verified, the current transaction is added to the list of valid_transactions.
-   After every transaction, the current state of the economy is displayed.
-   How to run the file: `python validate_transactions.py`

### Hash Function

We have used the following hash function to cryptographically hash the public key used for our P2PKH script: RIPEMD-160

-   RIPEMD-160 (RACE Integrity Primitives Evaluation Message Digest) is a cryptographic hash function designed to produce a 160-bit (20-byte) hash value.
-   How to run the file: `python ripemd.py`
-   If you need to hash some message/key, it is to be provided in the main in the `data` variable.
