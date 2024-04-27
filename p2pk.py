import ecdsa
import base64

# Create a message to sign
message = b"Hello, world!"

def validate_signature(public_key, signature, message):
    """Verifies if the signature is correct.

    This function verifies whether a given signature is valid for the provided message
    and public key.

    Args:
        public_key (str): The Base64 encoded public key.
        signature (str): The Base64 encoded signature.
        message (bytes): The message to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
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
        print("\nSignature verification failed:", e)
        return False


def validate_script(locking_script, unlocking_script, message):
    """Validates a Bitcoin transaction script.

    This function validates a Bitcoin transaction script by verifying the unlocking script
    with the locking script.

    Args:
        locking_script (bytes): The locking script (ScriptPubKey) of the transaction output.
        unlocking_script (bytes): The unlocking script (ScriptSig) of the transaction input.
        message (bytes): The message to verify.

    Returns:
        bool: True if the script is valid, False otherwise.
    """
    signature_length = unlocking_script[0]
    signature = unlocking_script[1:1 + signature_length]

    public_key_length = locking_script[0]
    public_key = locking_script[1:1 + public_key_length]

    if int(locking_script[1 + public_key_length:].hex(), 16) != 0xac:  # OP_CHECKSIG
        return False    
    
    if not validate_signature(base64.b64encode(public_key).decode(), base64.b64encode(signature).decode(), message):
        return False
    
    return True


def create_unlocking_script(signature):
    """Creates the unlocking script (ScriptSig) for a P2PK transaction.

    This function creates the unlocking script (ScriptSig) for a Pay-to-Public-Key (P2PK) Bitcoin transaction.

    Args:
        signature (bytes): The signature to be included in the unlocking script.

    Returns:
        bytes: The unlocking script bytes.
    """
    # Signature length
    signature_length = len(signature).to_bytes(1, byteorder='little')

    # Concatenate signature length, signature
    unlocking_script = signature_length + signature
    return unlocking_script


def create_locking_script(public_key):
    """Creates the locking script (ScriptPubKey) for a P2PK transaction.

    This function creates the locking script (ScriptPubKey) for a P2PK Bitcoin transaction.

    Args:
        public_key (bytes): The public key to be included in the locking script.

    Returns:
        bytes: The locking script bytes.
    """
    public_key_length = len(public_key).to_bytes(1, byteorder='little')
    locking_script = public_key_length + public_key
    locking_script += b'\xac' # OP_CHECKSIG

    # # to manipulate the locking script
    # locking_script += b'\x00' # OP_0
    # locking_script = locking_script[:-1] + b'\x00' # Change the last byte

    return locking_script


def main():
    # Generate a private key
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    # Get the corresponding public key
    public_key = private_key.verifying_key.to_string()

    # Sign the message
    signature = private_key.sign(message)

    # Print the signature and public key
    print("\nPrivate Key:", private_key.to_string().hex())
    print("Signature:", signature.hex())
    print("Public Key:", public_key.hex())

    locking_script = create_locking_script(public_key)
    print("\nLocking Script:", locking_script.hex())
    # print(len(locking_script))

    # # to manipulate the unlocking script
    # signature = signature + b"\x00" * 10  # Add 10 extra bytes to the signature
    # signature = b"\x00" * 64  # Change to an incorrect value

    unlocking_script= create_unlocking_script(signature)
    print("\nUnlocking Script:", unlocking_script.hex())

    # Validate the scripts
    valid = validate_script(locking_script, unlocking_script, message)
    print("\nScript is valid:", valid)

if __name__ == "__main__":
    main()
