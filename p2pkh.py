import ecdsa
# import hashlib
import base64
from hash_function import calc_hash

# Create a message to sign
message = b"Hello, world!"

def generate_key_pair():
    """
    Generates a private key, signs a message, and returns the signature and public key hash.
    """
    # Generate a private key
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    # Get the corresponding public key
    public_key = private_key.verifying_key.to_string()

    # Sign the message
    signature = private_key.sign(message)

    # Generate the public key hash
    public_key_hash = generate_public_key_hash(str(public_key))
    return private_key, public_key, signature, public_key_hash
   

def validate_signature(public_key, signature, message):
    """
    Verifies if the signature is correct.

    Parameters:
    - public_key (str): The Base64 encoded public key.
    - signature (str): The Base64 encoded signature.
    - message (bytes): The message to verify.

    Returns:
    - bool: True if the signature is valid, False otherwise.
    """
    try:
        # Decode public key and signature from base64
        public_key_bytes = base64.b64decode(public_key)
        signature_bytes = base64.b64decode(signature)
        
        # Convert public key bytes to hex
        public_key_hex = public_key_bytes.hex()

        # Initialize verifying key
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)
        
        # Verify signature
        if vk.verify(signature_bytes, message):
            return True
        else:
            print("\nSignature verification failed: Signature is invalid.")
            return False
    except ValueError:
        print("\nSignature verification failed: Invalid public key or signature format.")
        return False
    except ecdsa.BadSignatureError:
        print("\nSignature verification failed: Bad signature.")
        return False
  

def parse_locking_script(locking_script):
    """
    Parses the components of the locking script.

    Parameters:
    - locking_script (bytes): The locking script bytes.

    Returns:
    - list: List of parsed components.
    """
    components = []
    i = 0
    while i < len(locking_script):
        opcode = locking_script[i]
        i += 1
        if opcode == 0x76:  # OP_DUP
            components.append("OP_DUP")
        elif opcode == 0xa9:  # OP_HASH160
            components.append("OP_HASH160")
        elif opcode == 0x88:  # OP_EQUALVERIFY
            components.append("OP_EQUALVERIFY")
        elif opcode == 0xac:  # OP_CHECKSIG
            components.append("OP_CHECKSIG")
        elif opcode == 0x14:  # Push 20 bytes (OP_PUSHDATA1)
            components.append(locking_script[i:i + 20].hex())
            i += 20
        else:
            components.append("UNKNOWN_OPCODE_" + str(opcode))
    return components


def parse_unlocking_script(unlocking_script):
    """
    Parses the unlocking script.

    Parameters:
    - unlocking_script (bytes): The unlocking script bytes.

    Returns:
    - tuple: Signature and public key extracted from the unlocking script.
    """
    # Assuming the unlocking script contains the signature followed by the public key
    signature = unlocking_script[1:65]  # Assuming the signature length is 64 bytes (for ECDSA)
    public_key = unlocking_script[66:]  # Assuming the rest of the unlocking script is the public key
    return signature, public_key


def validate_script(locking_script, unlocking_script, message):
    """
    Validates a Bitcoin transaction script.

    Parameters:
    - locking_script (bytes): The locking script bytes.
    - unlocking_script (bytes): The unlocking script bytes.
    - message (bytes): The message to verify.

    Returns:
    - bool: True if the script is valid, False otherwise.
    """
    parsed_components = parse_locking_script(locking_script)
    # print("\nParsed components from locking_script: ", parsed_components)

    signature, public_key = parse_unlocking_script(unlocking_script)
    # print("\nSignature:", signature.hex())
    # print("Public Key:", public_key.hex())
    
    stack = []

    stack.append(signature)
    stack.append(public_key)

    i = 0
    while i < len(locking_script):
        # print("\nCurrent Stack View: ")  # Print items in hexadecimal format
        # # Create an iterator for the stack
        # stack_iterator = reversed(stack)

        # # Iterate through the stack
        # for element in stack_iterator:
        #     if element==signature:
        #         print("SIGNATURE : ",element.hex())
        #     if element.hex()==parsed_components[2]:
        #         print("PUBLIC KEY HASH : ",element.hex())
        #     if element==public_key:
        #         print("PUBLIC KEY : ",element.hex())
        opcode = locking_script[i]
        i += 1
        if opcode == 0x76:  # OP_DUP
            if len(stack) < 1:
                return False
            stack.append(stack[-1])
        elif opcode == 0xa9:  # OP_HASH160
            if len(stack) < 1:
                return False
            item = stack.pop()

            custom_hash = calc_hash(str(item))
            # print("\nHashed item pushed:",custom_hash.hex())
            
            stack.append(bytes.fromhex(custom_hash))

            # # Use hashlib.new with 'ripemd160' to hash the byte representation
            # hash_item = hashlib.new('ripemd160', hashlib.sha256(item).digest()).digest()
            # ripemd160_hash = hashlib.new('ripemd160', hash_item.encode('utf-8')).digest()
            # stack.append(ripemd160_hash)

        elif opcode == 0x14:  # Push 20 bytes (OP_PUSHDATA1)
            public_key_hash = locking_script[i:i + 20]
            stack.append(public_key_hash)
            i += 20
        elif opcode == 0x88:  # OP_EQUALVERIFY
            if len(stack) < 2:
                return False
            item1 = stack.pop()
            item2 = stack.pop()
            # print("\nitem1 :",item1.hex())
            # print("item2 :",item2.hex())

            if item1 != item2:
                return False
        elif opcode == 0xac:  # OP_CHECKSIG
            if len(stack) < 2:
                return False
            # Signature verification
            public_key = stack.pop()
            signature = stack.pop()
            if not validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), message):
                return False
            stack.append(True)
        else:
            # Unknown opcode
            return False

    # print("\nCurrent Stack View: ",stack)

    if len(stack) == 1 and stack[-1] == True:
        return True
    else:
        return False


def create_unlocking_script(signature, public_key):
    """
    Creates the unlocking script (ScriptSig) for a P2PKH transaction.

    Parameters:
    - signature (bytes): The signature to be included in the unlocking script.
    - public_key (bytes): The public key to be included in the unlocking script.

    Returns:
    - bytes: The unlocking script bytes.
    """
    # Signature length
    signature_length = len(signature).to_bytes(1, byteorder='little')
    # Public key length
    public_key_length = len(public_key).to_bytes(1, byteorder='little')

    # Concatenate signature length, signature, public key length, and public key
    unlocking_script = signature_length + signature + public_key_length + public_key
    return unlocking_script


def create_locking_script(public_key_hash):
    """
    Creates the locking script (ScriptPubKey) for a P2PKH transaction.

    Parameters:
    - public_key_hash (bytes): The public key hash to be included in the locking script.

    Returns:
    - bytes: The locking script bytes.
    """
    # P2PKH locking script structure:
    # OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG

    # OP_DUP (0x76): Duplicates the top stack item
    # OP_HASH160 (0xa9): Hashes the top stack item with SHA-256 followed by RIPEMD-160
    # <pubKeyHash>: Pushes the public key hash onto the stack
    # OP_EQUALVERIFY (0x88): Ensures the top two stack items are equal and removes them
    # OP_CHECKSIG (0xac): Verifies the signature of the input data

    locking_script = bytes.fromhex(f"76a914{public_key_hash}88ac")

    # # to manipulate the locking script
    # locking_script += b'\x00' # OP_0

    return locking_script


def generate_public_key_hash(public_key):
    """
    Generates the public key hash for a given public key.

    Parameters:
    - public_key (bytes): The public key to hash.

    Returns:
    - bytes: The public key hash.
    """

    # # Hash the public key (SHA-256 followed by RIPEMD-160)
    # sha256_hash = hashlib.sha256(public_key).digest()
    # ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    # return ripemd160_hash

    custom_hash = calc_hash(str(public_key))
    return custom_hash


def main():
    private_key, public_key, signature, public_key_hash = generate_key_pair()

    print("\nPrivate Key:", private_key.to_string().hex())
    print("Signature:", signature.hex())
    print("Public Key:", public_key.hex())
    print("Public Key Hash:", public_key_hash)

    # # to manipulate the locking script
    # public_key_hash = (bytes.fromhex(public_key_hash)[:-1] + b"\x00").hex()  # Change the last byte

    locking_script = create_locking_script(public_key_hash)
    print("\nLocking Script: ", locking_script.hex())
    # print(len(locking_script))

    # # to manipulate the unlocking script
    # signature = b"\x00" * 64  # Change to an incorrect value
    # signature = signature + b"\x00" * 10  # Add 10 extra bytes to the signature

    unlocking_script = create_unlocking_script(signature, public_key)
    print("\nUnlocking Script: ", unlocking_script.hex())

    # # to manipulate the unlocking script
    # unlocking_script = unlocking_script + b"\xac" # Add an additional opcode at the end of the unlocking script

    valid = validate_script(locking_script, unlocking_script, message)
    print("\nScript is valid:", valid)

if __name__ == "__main__":
    main()