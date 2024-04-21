import ecdsa
import hashlib
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

def validate_script(locking_script, unlocking_script, message):
    signature_length = unlocking_script[0]
    signature = unlocking_script[1:1 + signature_length]
    # print(signature.hex())  

    public_key_length = locking_script[0]
    public_key = locking_script[1:1 + public_key_length]
    # print(public_key.hex())

    # print(locking_script[1 + public_key_length:].hex())
    if int(locking_script[1 + public_key_length:].hex(), 16) != 0xac:  # OP_CHECKSIG
        print(1)
        return False    
    
    if not validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), message):
        print(2)
        return False
    
    return True


def create_unlocking_script(signature):
    """
    Creates the unlocking script (ScriptSig) for a P2PK transaction.

    Parameters:
    - signature (bytes): The signature to be included in the unlocking script.

    Returns:
    - bytes: The unlocking script bytes.
    """
    # Signature length
    signature_length = len(signature).to_bytes(1, byteorder='little')

    # Concatenate signature length, signature
    unlocking_script = signature_length + signature
    return unlocking_script

def create_locking_script(public_key):
    """
    Creates the locking script (ScriptPubKey) for a P2PK transaction.

    Parameters:
    - public_key (bytes): The public key to be included in the locking script.

    Returns:
    - bytes: The locking script bytes.
    """
    public_key_length = len(public_key).to_bytes(1, byteorder='little')
    locking_script = public_key_length + public_key
    locking_script += b'\xac' # OP_CHECKSIG

    # to manipulate the locking script
    # locking_script += b'\x00' # OP_0

    return locking_script


# Generate a private key
private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

# Get the corresponding public key
public_key = private_key.verifying_key.to_string()

# Create a message to sign
message = b"Hello, world!"

# Sign the message
signature = private_key.sign(message)

# Print the signature and public key
print("Signature:", signature.hex())
print("Public Key:", public_key.hex())

# Call the validate_signature function
# print(validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), message))

locking_script = create_locking_script(public_key)
# print(len(locking_script))

# to manipulate the unlocking script
# signature = private_key.sign(message)+b'\x01'

unlocking_script= create_unlocking_script(signature)

# Validate the scripts
valid = validate_script(locking_script, unlocking_script, message)
print("Script is valid:", valid)