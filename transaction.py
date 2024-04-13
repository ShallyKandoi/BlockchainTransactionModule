import hashlib
import ecdsa

opcode_to_name = {
    b"\x76": "OP_DUP",
    b"\xa9": "OP_HASH160",
    b"\x14": "PUSHDATA20",
    b"\x88": "OP_EQUALVERIFY",
    b"\xac": "OP_CHECKSIG"
    }

class Transaction:
    def __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs

    def serialize(self):
        serialized_inputs = b"".join([input.serialize() for input in self.inputs])
        serialized_outputs = b"".join([output.serialize() for output in self.outputs])
        num_inputs_bytes = len(self.inputs).to_bytes(4, byteorder='little')
        num_outputs_bytes = len(self.outputs).to_bytes(4, byteorder='little')
        return num_inputs_bytes + serialized_inputs + num_outputs_bytes + serialized_outputs
    
    @staticmethod
    def deserialize(data):
        inputs = []
        outputs = []

        num_inputs = int.from_bytes(data[:4], byteorder='little')
        data = data[4:]
        for _ in range(num_inputs):
            input_length = int.from_bytes(data[:4], byteorder='little')
            input_data = data[4:4+input_length]
            inputs.append(Input.deserialize(input_data))
            data = data[4+input_length:]

        num_outputs = int.from_bytes(data[:4], byteorder='little')
        data = data[4:]
        for _ in range(num_outputs):
            output_length = int.from_bytes(data[:4], byteorder='little')
            output_data = data[4:4+output_length]
            outputs.append(Output.deserialize(output_data))
            data = data[4+output_length:]

        return Transaction(inputs, outputs)

class ScriptInterpreter:
    def __init__(self):
        pass

    def execute_script(self, script, public_key_hash, signature):
        stack = []

        for opcode in script:
            print(opcode)
            if opcode == "OP_DUP":
                self.op_dup(stack)
            elif opcode == "OP_HASH160":
                self.op_hash160(stack)
            elif opcode == "OP_EQUALVERIFY":
                self.op_equalverify(stack)
            elif opcode == "OP_CHECKSIG":
                self.op_checksig(stack, public_key_hash, signature)
            elif opcode == "PUSHDATA65":
                stack.append(public_key_hash)
            elif opcode == "PUSHDATA73":
                stack.append(signature)
            else:
                raise ValueError("Unsupported opcode")

        return stack[-1] == True

    def op_dup(self, stack):
        stack.append(stack[-1])

    def op_hash160(self, stack):
        item = stack.pop()
        stack.append(hashlib.new('ripemd160', hashlib.sha256(item).digest()).digest())

    def op_equalverify(self, stack):
        item1 = stack.pop()
        item2 = stack.pop()
        if item1 != item2:
            raise ValueError("OP_EQUALVERIFY failed")

    def op_checksig(self, stack):
        pubkey = stack.pop()
        signature = stack.pop()
        if not self.verify_signature(signature, pubkey):
            raise ValueError("Invalid signature")
        stack.append(True)

    def verify_signature(self, signature, pubkey):
        pubkey_point = ecdsa.VerifyingKey.from_string(pubkey[1:], curve=ecdsa.SECP256k1)
        return pubkey_point.verify(signature[1:], b"message", hashfunc=hashlib.sha256)

class Input:
    def __init__(self, script, signature):
        self.script = script
        self.signature = signature

    def serialize(self):
        serialized_script = b"".join([self.opcode_to_bytes(opcode) for opcode in self.script])
        serialized_signature = len(self.signature).to_bytes(4, byteorder='little') + self.signature
        return len(serialized_script).to_bytes(4, byteorder='little') + serialized_script + serialized_signature

    @staticmethod
    def opcode_to_bytes(opcode):
        if opcode == "OP_DUP":
            return b"\x76"  # Hexadecimal representation of OP_DUP
        elif opcode == "OP_HASH160":
            return b"\xa9"  # Hexadecimal representation of OP_HASH160
        elif opcode == "PUSHDATA20":
            return b"\x14"  # Hexadecimal representation of PUSHDATA20
        elif opcode == "OP_EQUALVERIFY":
            return b"\x88"  # Hexadecimal representation of OP_EQUALVERIFY
        elif opcode == "OP_CHECKSIG":
            return b"\xac"  # Hexadecimal representation of OP_CHECKSIG
        else:
            raise ValueError("Unsupported opcode")
    
    @staticmethod
    def deserialize(data):
        script_length = int.from_bytes(data[:4], byteorder='little')
        script_data = data[4:4+script_length]

        script = []
        i = 0
        while i < len(script_data):
            opcode = script_data[i]
            if opcode in opcode_to_name:
                script.append(opcode_to_name[opcode])
                i += 1
            else:
                raise ValueError("Unknown opcode")
        
        signature_length = int.from_bytes(data[4+script_length:4+script_length+4], byteorder='little')
        signature = data[4+script_length+4:4+script_length+4+signature_length]
        return Input(script, signature)

class Output:
    def __init__(self, value, script_pubkey):
        self.value = value
        self.script_pubkey = script_pubkey

    def serialize(self):
        script_pubkey_bytes = self.script_pubkey.encode()  # Convert string to bytes
        return len(script_pubkey_bytes).to_bytes(4, byteorder='little') + script_pubkey_bytes + self.value.to_bytes(8, byteorder='little', signed=False)
    
    @staticmethod
    def deserialize(data):
        script_length = int.from_bytes(data[:4], byteorder='little')
        script_pubkey = data[4:4+script_length]
        value = int.from_bytes(data[4+script_length:], byteorder='little', signed=False)
        return Output(value, script_pubkey)

# Example usage
# Define scripts for inputs and outputs
input_script = [
    "OP_DUP",
    "OP_HASH160",
    "PUSHDATA20",  # Push 20 bytes (public key hash)
    "OP_EQUALVERIFY",
    "OP_CHECKSIG"
]
output_script = "P2PKHScript"

# Example public key hash and signature
public_key_hash = b'\x60\xac\xda\xf1\x6b\xb0\x88\x8a\x26\x6f\x0c\x7c\x28\x62\x58\x89\x51\x58\x00\x00'
signature = b'\x30\x45\x02\x21\x00\xed\x3c\x2e\xbc\x78\x14\x12\x64\x09\x2b\x1e\x85\x6e\xaf\x4b\x42\x3c\x8f\x67\x9f\x72\x7f\x68\xb2\xf1\x3b\x9d\x80\xba\x02\x20\x33\x6d\x9d\x0e\xc2\xc0\x63\xc4\x0e\x6d\x9e\x5f\xf7\x46\x0a\x22\x63\x79\x90\x36\x3c\x43\x7b\x9f\x85\x31\xfa\x06\x17'

# Create transaction
inputs = [Input(input_script, signature)]
outputs = [Output(10, output_script)]
transaction = Transaction(inputs, outputs)
print(transaction.inputs[0].script)

# Serialize and deserialize transaction
serialized_transaction = transaction.serialize()
print(serialized_transaction)
print()
deserialized_transaction = Transaction.deserialize(serialized_transaction)

print(serialized_transaction)
print()
print(deserialized_transaction.inputs[0].script)

# Validate transaction
interpreter = ScriptInterpreter()
for input in deserialized_transaction.inputs:
    is_valid = interpreter.execute_script(input.script, public_key_hash, input.signature)
    print("Input is valid:", is_valid)
