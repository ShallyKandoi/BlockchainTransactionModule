import ecdsa
import hashlib
from ecdsa.util import sigdecode_der
from ecdsa.keys import VerifyingKey
from ecdsa.curves import SECP256k1
from ecdsa import der
import base64

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
    print("Signature:", signature.hex())
    print("Public Key:", public_key.hex())
    
    stack = []

    stack.append(signature)
    stack.append(public_key)

    for opcode in locking_script:
        if opcode == 0x76:  # OP_DUP
            if len(stack) < 1:
                return False
            stack.append(stack.top())
        elif opcode == 0xA9:  # OP_HASH160
            if len(stack) < 1:
                return False
            item = stack.pop()
            hash_item = hashlib.new('ripemd160', hashlib.sha256(item).digest()).digest()
            stack.append(hash_item)
        elif opcode == 0x14:  # PUSH20
            # Extract next 20 bytes as public key hash
            public_key_hash = locking_script[:20]
            locking_script = locking_script[20:]
            stack.append(public_key_hash)
        elif opcode == 0x88:  # OP_EQUALVERIFY
            if len(stack) < 2:
                return False
            item1 = stack.pop()
            item2 = stack.pop()
            if item1 != item2:
                return False
        elif opcode == 0xAC:  # OP_CHECKSIG
            if len(stack) < 2:
                return False
            # Signature verification
            public_key_bytes = base64.b64decode(stack.pop())
            signature_bytes = base64.b64decode(stack.pop())

            try:
                # Initialize verifying key
                vk = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)

                # Verify signature
                if not vk.verify(signature_bytes, message):
                    return False
            except (ValueError, ecdsa.BadSignatureError) as e:
                # Handle specific exceptions
                print("Signature verification failed:", e)
                return False
        else:
            # Unknown opcode
            return False

    if len(stack) == 1 and stack[-1] == True:
        return True
    else:
        return False

def validate_scripts(locking_script, unlocking_script, public_key_hash,public_key,signature):
    """
    Validates the locking and unlocking scripts for a P2PKH transaction.

    Parameters:
    - locking_script (bytes): The locking script (ScriptPubKey) of the output.
    - unlocking_script (bytes): The unlocking script (ScriptSig) of the input.
    - public_key_hash (bytes): The public key hash used in the locking script.
    - signature (bytes): The signature provided in the unlocking script.
    - public_key (bytes): The public key provided in the unlocking script.

    Returns:
    - bool: True if the scripts are valid, False otherwise.
    """
    # Validate unlocking script:
    # 1. Check if the unlocking script length is correct.
    if len(unlocking_script) != len(signature) + len(public_key) + 2:
        return False

    # 2. Verify the signature using the public key and the public key hash.
    if not validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), b"Hello, world!"):
        return False

    # Validate locking script:
    # 1. Check if the locking script length is correct.
    if len(locking_script) != 25:
        return False

    # 2. Extract the public key hash from the locking script.
    extracted_public_key_hash = locking_script[3:23]

    # 3. Compare the extracted public key hash with the provided public key hash.
    if extracted_public_key_hash != public_key_hash:
        print(2)
        return False

    # Both scripts are valid.
    return True

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
    return locking_script
# Generate a private key
private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

# Get the corresponding public key
public_key = private_key.verifying_key.to_string()

# Create a message to sign
message = b"Hello, world!"

# Sign the message
signature = private_key.sign(message)

def generate_public_key_hash(public_key):
    # Step 2: Hash the public key (SHA-256 followed by RIPEMD-160)
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash

public_key_hash= generate_public_key_hash(public_key)

# Print the signature and public key
print("Signature:", signature.hex())
print("Public Key:", public_key.hex())
print("Public Key Hash:", public_key_hash.hex())

# Call the validate_signature function
print(validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), message))

# Example data
#public_key_hash = b'\x60\xac\xda\xf1\x6b\xb0\x88\x8a\x26\x6f\x0c\x7c\x28\x62\x58\x89\x51\x58\x00\x00'
locking_script = create_locking_script(public_key_hash)
print(len(locking_script))
#signature = bytes.fromhex("3045022100ed3c2ebc78141264092b1e856eaf4b423c8f679f727f68b2f13b9d80ba0220336d9d0ec2c063c40e6d9e5ff7460a22637990363c437b9f8531fa0617")
#public_key = bytes.fromhex("040209d1b6372a7d8abef7a52364955ed29bdea30f312619b745515936b01bcc95e4843f5198d220a465b2eb69dcfd446438fbfd37eb20365e3e36e99fbc5ca54897")
unlocking_script= create_unlocking_script(signature, public_key)

# Example usage:
#locking_script = bytes.fromhex("76a9140102030405060708090a0b0c0d0e0f1011121314a88ac")

# Example usage:
#unlocking_script = bytes.fromhex("3044022072d2a6fb587f25c3c5631546f37aef1333c35cf3b103eac71f614e9018ffedf8022046845d3e04198201b29cf45e6c8b72fd739c2f82cbda84f6ec948d92e1eab001")

# Validate the scripts
valid = validate_scripts(locking_script, unlocking_script, public_key_hash,public_key,signature)
valid = validate_script(locking_script, unlocking_script, message)
print("Scripts are valid:", valid)
