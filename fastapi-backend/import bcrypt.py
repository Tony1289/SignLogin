import bcrypt

def generate_hash(secret: str):
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()

if __name__ == "__main__":
    code = input("Enter the security code: ")
    print("Hashed Security Code:")
    print(generate_hash(code))
