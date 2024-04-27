import ecdsa
import base64
import random

# Create a message to sign
message = b"Hello, world!"

def generate_multisig_locking_script(num_signatures, public_keys):
    """
    Creates the locking script (ScriptPubKey) for a P2MS transaction.

    Parameters:
    - num_signatures (int): The number of required signatures.
    - public_keys (list): List of public keys (bytes) involved in the multisig setup.

    Returns:
    - bytes: The locking script bytes.
    """
    if num_signatures <= 0 or num_signatures > len(public_keys):
        raise ValueError("\nInvalid number of signatures")

    # Construct multisig locking script
    opcode_m = bytes([80 + num_signatures])     # OP_1 to OP_16
    opcode_n = bytes([80 + len(public_keys)])   # OP_1 to OP_16
    public_keys_bytes = b"".join([len(key).to_bytes(1, 'big') + key for key in public_keys])
    locking_script_bytes =  b"".join([opcode_m, public_keys_bytes, opcode_n, b"\xae"])  # OP_CHECKMULTISIG
    return locking_script_bytes

def generate_multisig_unlocking_script(signatures):
    """
    Creates the unlocking script (ScriptSig) for a P2MS transaction.

    Parameters:
    - signatures (list): List of signatures (bytes) corresponding to the public keys.

    Returns:
    - bytes: The unlocking script bytes.
    """
    opcode_signatures = bytes([len(signatures)])
    signatures_bytes = b"".join([len(sig).to_bytes(1, 'big') + sig for sig in signatures])
    return b"".join([opcode_signatures, signatures_bytes])

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
        print("\nSignature verification failed:", e)
        return False

def parse_locking_script(locking_script):
    """
    Parses the components of a locking script (ScriptPubKey) for a P2MS transaction.

    Parameters:
    - locking_script (bytes): The locking script bytes.

    Returns:
    - list: List of components extracted from the locking script.
    """
    components = []
    components.append(locking_script[0] - 80)
    public_keys = []
    i = 1
    while i < len(locking_script) - 2:  # Ensure there are enough bytes for the last two components
        if locking_script[i] == 0xae:  # OP_CHECKMULTISIG opcode
            break
        key_length = locking_script[i]
        i += 1
        if i + key_length > len(locking_script):
            raise ValueError("\nInvalid locking script format: Key length exceeds script length")
        public_keys.append(locking_script[i:i + key_length].hex())
        i += key_length
    components += public_keys
    components.append(locking_script[i] - 80)
    if locking_script[i+1] == 0xae:  # OP_CHECKMULTISIG opcode
        components.append('OP_CHECKMULTISIG')
    return components

def parse_unlocking_script(unlocking_script):
    """
    Parses the components of an unlocking script (ScriptSig) for a P2MS transaction.

    Parameters:
    - unlocking_script (bytes): The unlocking script bytes.

    Returns:
    - list: List of signatures extracted from the unlocking script.
    """
    # num_signatures = unlocking_script[0]
    sigs = []
    i = 1
    while i < len(unlocking_script):
        sig_length = unlocking_script[i]
        sig = unlocking_script[i + 1: i + 1 + sig_length]
        sigs.append(sig.hex())
        i += sig_length + 1
    return sigs

def validate_multisig_script(locking_script, unlocking_script, message):
    """
    Validates the unlocking script against the locking script for a P2MS transaction.

    Parameters:
    - locking_script (bytes): The locking script bytes.
    - unlocking_script (bytes): The unlocking script bytes.
    - message (bytes): The message to be signed.

    Returns:
    - bool: True if the scripts are valid, False otherwise.
    """
    components = parse_locking_script(locking_script)
    print("\nParsed components from Locking Script: ", components)

    parsed_unlocking_script = parse_unlocking_script(unlocking_script)
    print("\nParsed components from Unlocking Script: ", parsed_unlocking_script)

    stack = []

    for signature in parsed_unlocking_script:
        stack.append(signature)

    checkMultiSig = False
    for i in range(len(components)):

        print("\n Current Stack View: ",stack)

        if components[i] == 'OP_CHECKMULTISIG':
            checkMultiSig = True
            break
        stack.append(components[i])

    if not checkMultiSig:
        return False
    
    pubkeys = []
    signatures = []
    
    if checkMultiSig:
        if not isinstance(stack[-1], int):
            return False
        num_pub_keys = stack.pop()
        for i in range(num_pub_keys):
            if not isinstance(stack[-1], str):
                return False
            pubkeys.append(bytes.fromhex(stack.pop()))
        if not isinstance(stack[-1], int):
            return False
        num_signatures_required = stack.pop()
        if len(stack) != num_signatures_required:
            return False
        for i in range(num_signatures_required):
            if not isinstance(stack[-1], str):
                return False
            signatures.append(bytes.fromhex(stack.pop()))
        if len(stack) != 0:
            return False

    if num_signatures_required > num_pub_keys:
        return False  # More signatures than public keys, invalid
    
    # Ensure all signatures and their corresponding public keys are distinct
    if len(set(signatures)) != num_signatures_required or len(set(pubkeys)) != num_pub_keys:
        return False
    
    matched_pairs = set()  # Store matched pairs of signature and public key indices
    last_matched_pubkey_index = -1  # Initialize index of last matched public key

    for sig_index, sig in enumerate(signatures):
        for pubkey_index in range(last_matched_pubkey_index + 1, len(pubkeys)):
            pubkey = pubkeys[pubkey_index]
            if validate_signature(base64.b64encode(pubkey).decode(), base64.b64encode(sig).decode(), message):
                print("\nSignature verified {}: {}".format(sig_index+1, sig.hex()))
                print("Corresponding Public key: ", pubkey.hex())
                matched_pairs.add((sig_index, pubkey_index))
                last_matched_pubkey_index = pubkey_index # Update index of last matched public key
                break
        
    if len(matched_pairs) == num_signatures_required:
        print("\nRequired number of signatures verified")
        return True
    else:
        print("\nSignature verification failed")
        return False


def main():
    try:
        # Prompt user for the number of required signatures
        num_signatures = int(input("\nEnter the number of required signatures: "))
        if num_signatures <= 0:
            raise ValueError("\nNumber of required signatures must be positive")

        # Prompt user for the number of public keys required to lock
        num_pubkeys_lock = int(input("Enter the number of public keys required to lock: "))
        if num_pubkeys_lock <= 0:
            raise ValueError("\nNumber of public keys required to lock must be positive")

        print("\n")

        # Generate a set of public keys using the ECDSA algorithm
        public_keys = []
        signatures = []
        for idx in range(num_pubkeys_lock):
            private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            public_key = private_key.verifying_key.to_string()
            print("Public Key [{}]: {}".format(idx+1, public_key.hex()))
            public_keys.append(public_key)

            signature = private_key.sign(message)
            print("Signature [{}]: {}".format(idx+1, signature.hex()))

            # # to manipulate the unlocking script
            # signature = signature + b'\x01'
            # signature = b"\x00" * 64  # Change to an incorrect value

            signatures.append(signature)

         # Randomly select num_signatures from the set of all signatures
        selected_signatures_indices = random.sample(range(num_pubkeys_lock), num_signatures)
        selected_signatures_indices.sort()
        print("\nSelected Signature Indices:", selected_signatures_indices)
        selected_signatures = [signatures[i] for i in selected_signatures_indices]
        selected_signatures_hex = [signature.hex() for signature in selected_signatures]
        # print("\nSelected Signatures:", selected_signatures_hex)

        # Locking script
        locking_script = generate_multisig_locking_script(num_signatures, public_keys)
        print("\nLocking Script:", locking_script.hex())

        # Unlocking script
        unlocking_script = generate_multisig_unlocking_script(selected_signatures)

        # # to manipulate the unlocking script
        # unlocking_script = generate_multisig_unlocking_script(selected_signatures)+b'\x01'

        print("\nUnlocking Script:", unlocking_script.hex())

        # Validate the scripts 
        valid = validate_multisig_script(locking_script, unlocking_script, message)
        print("\nScript is valid:", valid)

    except ValueError as e:
        print("\nError:", e)

if __name__ == "__main__":
    main()
