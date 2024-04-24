import ecdsa
import hashlib
import base64
from custom_hash_func import hash

def validate_signature(public_key, signature, message):
    """Verifies if the signature is correct. This is used to prove
    it's you (and not someone else) trying to do a transaction with your
    address. Called when a user tries to submit a new transaction.
    """
    # Decode public key and signature from base64
    public_key_bytes = base64.b64decode(public_key)
    signature_bytes = base64.b64decode(signature)
    
    # Convert public key bytes to hex
    public_key_hex = public_key_bytes.hex()

    try:
        # Initialize verifying key
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)
        
        # Verify signature
        return vk.verify(signature_bytes, message)
    except (ValueError, ecdsa.BadSignatureError) as e:
        # Handle specific exceptions
        print("Signature verification failed:", e)
        return False
    

def parse_locking_script(locking_script):
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
    # Assuming the unlocking script contains the signature followed by the public key
    signature = unlocking_script[1:65]  # Assuming the signature length is 64 bytes (for ECDSA)
    public_key = unlocking_script[66:]  # Assuming the rest of the unlocking script is the public key
    return signature, public_key


def validate_script(locking_script, unlocking_script, message):
    parsed_components = parse_locking_script(locking_script)
    print(parsed_components)

    signature, public_key = parse_unlocking_script(unlocking_script)
    # print("Signature:", signature.hex())
    # print("Public Key:", public_key.hex())
    
    stack = []

    stack.append(signature)
    stack.append(public_key)

    i = 0
    while i < len(locking_script):
        # print(stack)
        # print()
        opcode = locking_script[i]
        i += 1
        if opcode == 0x76:  # OP_DUP
            if len(stack) < 1:
                # print(1)
                return False
            stack.append(stack[-1])
        elif opcode == 0xa9:  # OP_HASH160
            if len(stack) < 1:
                # print(2)
                return False
            item = stack.pop()
            hash_item = hash(str(item))
            # Use hashlib.new with 'ripemd160' to hash the byte representation
            ripemd160_hash = hashlib.new('ripemd160', hash_item.encode('utf-8')).digest()
            stack.append(ripemd160_hash)
            # print("Hashed item pushed:",ripemd160_hash.hex())
            # hash_item = hashlib.new('ripemd160', hashlib.sha256(item).digest()).digest()
            # stack.append(hash_item)
        elif opcode == 0x14:  # Push 20 bytes (OP_PUSHDATA1)
            # Extract next 20 bytes as public key hash
            # public_key_hash = locking_script[i:i + 20].hex()
            public_key_hash = locking_script[i:i + 20]
            stack.append(public_key_hash)
            i += 20
        elif opcode == 0x88:  # OP_EQUALVERIFY
            if len(stack) < 2:
                # print(3)
                return False
            item1 = stack.pop()
            item2 = stack.pop()
            if item1 != item2:
                # print(4)
                return False
        elif opcode == 0xac:  # OP_CHECKSIG
            # print(stack)
            if len(stack) < 2:
                # print(5)
                return False
            # Signature verification
            public_key = stack.pop()
            signature = stack.pop()
            if not validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), message):
                # print(6)
                return False
            stack.append(True)
        else:
            # Unknown opcode
            # print(7)
            return False

    # print(stack)

    if len(stack) == 1 and stack[-1] == True:
    # if stack.empty():
        return True
    else:
        # print(8)
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

    locking_script = bytes.fromhex(f"76a914{public_key_hash.hex()}88ac")
    # print("lo:", locking_script)
    return locking_script


def generate_public_key_hash(public_key):
    # Step 2: Hash the public key (SHA-256 followed by RIPEMD-160)
    # Use hashlib.new with 'ripemd160' to hash the byte representation
    # sha256_hash = hashlib.sha256(public_key).digest()
    # ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    custom_hash_output = hash(public_key)
    ripemd160_hash = hashlib.new('ripemd160', custom_hash_output.encode('utf-8')).digest()
    return ripemd160_hash


# Generate a private key
private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

# Get the corresponding public key
public_key = private_key.verifying_key.to_string()

# Create a message to sign
message = b"Hello, world!"

# Sign the message
signature = private_key.sign(message)

public_key_hash= generate_public_key_hash(str(public_key))

# Print the signature and public key
print("Signature:", signature.hex())
print("Public Key:", public_key.hex())
print("Public Key Hash:", public_key_hash.hex())

# Call the validate_signature function
# print(validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), message))

locking_script = create_locking_script(public_key_hash)
# print(len(locking_script))

# to manipulate the unlocking script
# signature = private_key.sign(message)+b'\x01'
# public_key = public_key+b'\x01'

unlocking_script= create_unlocking_script(signature, public_key)

# Validate the scripts
valid = validate_script(locking_script, unlocking_script, message)
print("Script is valid:", valid)