import ecdsa
import hashlib
import base64
import random

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
        raise ValueError("Invalid number of signatures")

    # Construct multisig locking script
    opcode_m = bytes([80 + num_signatures])  # OP_1 through OP_16
    opcode_n = bytes([80 + len(public_keys)])  # OP_1 through OP_16
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
        # print(1,end='\n')
        return vk.verify(signature_bytes, message)
    except (ValueError, ecdsa.BadSignatureError) as e:
        # Handle specific exceptions
        # print("Signature verification failed:", e)
        # print(2,end='\n')
        return False

def parse_locking_script(locking_script):
    components = []
    # components['m'] = locking_script[0] - 80  # Convert OP_1 through OP_16 to integer m
    components.append(locking_script[0] - 80)
    public_keys = []
    i = 1
    while i < len(locking_script) - 2:  # Ensure there are enough bytes for the last two components
        if locking_script[i] == 0xae:  # OP_CHECKMULTISIG opcode
            break
        key_length = locking_script[i]
        i += 1
        if i + key_length > len(locking_script):
            raise ValueError("Invalid locking script format: Key length exceeds script length")
        # public_keys.append(locking_script[i:i + key_length])
        public_keys.append(locking_script[i:i + key_length].hex())
        i += key_length
    # components['public_keys'] = public_keys
    components += public_keys
    # components.append(public_keys)
    # components['n'] = locking_script[i] - 80  # Number of public keys
    components.append(locking_script[i] - 80)
    # components['checkmultisig_opcode'] = locking_script[i + 1]  # OP_CHECKMULTISIG opcode
    components.append('OP_CHECKMULTISIG')
    return components

def parse_unlocking_script(unlocking_script):
    # num_signatures = unlocking_script[0]
    sigs = []
    i = 1
    while i < len(unlocking_script):
        sig_length = unlocking_script[i]
        sig = unlocking_script[i + 1: i + 1 + sig_length]
        sigs.append(sig.hex())
        i += sig_length + 1
    # return num_signatures, sigs
    return sigs

def validate_multisig_script(locking_script, unlocking_script, message):
    components = parse_locking_script(locking_script)
    print("Locking Script: ", components)

    parsed_unlocking_script = parse_unlocking_script(unlocking_script)
    print("Unlocking Script: ", parsed_unlocking_script)

    stack = []

    for signature in parsed_unlocking_script:
        stack.append(signature)

    checkMultiSig = False
    for i in range(len(components)):
        if components[i] == 'OP_CHECKMULTISIG':
            checkMultiSig = True
            break
        stack.append(components[i])
        
    # print("Stack: ",stack)

    if not checkMultiSig:
        # print(1,end='\n')
        return False
    
    pubkeys = []
    signatures = []
    
    if checkMultiSig:
        if not isinstance(stack[-1], int):
            # print(2,end='\n')
            return False
        num_pub_keys = stack.pop()
        for i in range(num_pub_keys):
            if not isinstance(stack[-1], str):
                # print(3,end='\n')
                return False
            pubkeys.append(bytes.fromhex(stack.pop()))
        if not isinstance(stack[-1], int):
            # print(4,end='\n')
            return False
        num_signatures_required = stack.pop()
        if len(stack) != num_signatures_required:
            # print(5,end='\n')
            return False
        for i in range(num_signatures_required):
            if not isinstance(stack[-1], str):
                # print(6,end='\n')
                return False
            signatures.append(bytes.fromhex(stack.pop()))
        if len(stack) != 0:
            # print(7,end='\n')
            return False

    if num_signatures_required > num_pub_keys:
        # print(8,end='\n')
        return False  # More signatures than public keys, invalid
    
    # Ensure all signatures and their corresponding public keys are distinct
    if len(set(signatures)) != num_signatures_required or len(set(pubkeys)) != num_pub_keys:
        # print(9,end='\n')
        return False
    
    matched_pairs = set()  # Store matched pairs of signature and public key indices
    last_matched_pubkey_index = -1  # Initialize index of last matched public key

    for sig_index, sig in enumerate(signatures):
        for pubkey_index in range(last_matched_pubkey_index + 1, len(pubkeys)):
            pubkey = pubkeys[pubkey_index]
        # for pubkey_index, pubkey in enumerate(pubkeys):
            # if (sig_index, pubkey_index) in matched_pairs:
                # continue  # Skip if this pair is already matched
            if validate_signature(base64.b64encode(pubkey).decode(), base64.b64encode(sig).decode(), message):
                print("Signature verified: ",sig.hex(),end='\n')
                print("Public key verified: ",pubkey.hex(),end='\n')
                matched_pairs.add((sig_index, pubkey_index))
                last_matched_pubkey_index = pubkey_index # Update index of last matched public key
                break
        
    # print(10,end='\n')
    if len(matched_pairs) == num_signatures_required:
        return True
    else:
        print("Signature verification failed")
        return False


def main():
    try:
        # Prompt user for the number of required signatures
        num_signatures = int(input("Enter the number of required signatures: "))
        if num_signatures <= 0:
            raise ValueError("Number of required signatures must be positive")

        # Prompt user for the number of public keys required to lock
        num_pubkeys_lock = int(input("Enter the number of public keys required to lock: "))
        if num_pubkeys_lock <= 0:
            raise ValueError("Number of public keys required to lock must be positive")

        message = b"Hello, world!"

        # Generate a set of public keys using the ECDSA algorithm
        public_keys = []
        signatures = []
        for _ in range(num_pubkeys_lock):
            private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            public_key = private_key.verifying_key.to_string()
            print("Public Key:", public_key.hex(),end='\n')
            public_keys.append(public_key)

            # to manipulate the unlocking script
            # signature = private_key.sign(message)+b'\x01'

            signature = private_key.sign(message)
            print("Signature:", signature.hex(),end='\n')
            signatures.append(signature)

         # Randomly select num_signatures from the set of all signatures
        selected_signatures_indices = random.sample(range(num_pubkeys_lock), num_signatures)
        selected_signatures_indices.sort()
        print("Selected Signature Indices:", selected_signatures_indices)
        selected_signatures = [signatures[i] for i in selected_signatures_indices]
        selected_signatures_hex = [signature.hex() for signature in selected_signatures]
        print("Selected Signatures:", selected_signatures_hex)

        # Locking script
        locking_script = generate_multisig_locking_script(num_signatures, public_keys)
        # print("Locking Script:", locking_script.hex(), end='\n')

        # Unlocking script
        unlocking_script = generate_multisig_unlocking_script(selected_signatures)
        # to manipulate the unlocking script
        # unlocking_script = generate_multisig_unlocking_script(selected_signatures)+b'\x01'
        # print("Unlocking Script:", unlocking_script.hex(),end='\n')

        # Validate the scripts (placeholder)
        valid = validate_multisig_script(locking_script, unlocking_script, message)
        print("Script is valid:", valid)

    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
