import ecdsa
from ecdsa.util import sigdecode_der

def validate_scripts(locking_script, unlocking_script, public_key_hash, signature, public_key):
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
    if not verify_signature(signature, public_key, public_key_hash):
        return False

    # Validate locking script:
    # 1. Check if the locking script length is correct.
    if len(locking_script) != 25:
        return False

    # 2. Extract the public key hash from the locking script.
    extracted_public_key_hash = locking_script[3:23]

    # 3. Compare the extracted public key hash with the provided public key hash.
    if extracted_public_key_hash != public_key_hash:
        return False

    # Both scripts are valid.
    return True

def verify_signature(signature, public_key, public_key_hash):
    # Convert the signature from DER format to (r, s) tuple
    sig = sigdecode_der(signature[1:])

    # Load the public key from its bytes representation
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)

    # Verify the signature
    return vk.verify(sig, public_key_hash, sigdecode=ecdsa.util.sigdecode_der)

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

# Example data
public_key_hash = b'\x60\xac\xda\xf1\x6b\xb0\x88\x8a\x26\x6f\x0c\x7c\x28\x62\x58\x89\x51\x58\x00\x00'
locking_script = create_locking_script(public_key_hash)
signature = bytes.fromhex("3045022100ed3c2ebc78141264092b1e856eaf4b423c8f679f727f68b2f13b9d80ba0220336d9d0ec2c063c40e6d9e5ff7460a22637990363c437b9f8531fa0617")
public_key = bytes.fromhex("040209d1b6372a7d8abef7a52364955ed29bdea30f312619b745515936b01bcc95e4843f5198d220a465b2eb69dcfd446438fbfd37eb20365e3e36e99fbc5ca54897")
unlocking_script= create_unlocking_script(signature, public_key)

# Validate the scripts
valid = validate_scripts(locking_script, unlocking_script, public_key_hash, signature, public_key)
print("Scripts are valid:", valid)
