import ecdsa

class User:
    def __init__(self, name, initial_money):
        self.name = name
        self.initial_money = initial_money
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()
    
    def generate_private_key(self):
        # Generate a random private key
        return ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    
    def generate_public_key(self):
        # Generate a public key based on the private key (this can be more complex in real scenarios)
        return self.private_key.verifying_key.to_string()
    
    def get_money(self):
        # Returns the initial balance
        return self.initial_money
    
    def get_private_key(self):
        # Returns the private key
        return self.private_key
    
    def get_public_key(self):
        # Returns the public key
        return self.public_key