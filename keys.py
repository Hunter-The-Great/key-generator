from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from argparse import ArgumentParser
import os


def main(args):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)

    if args.passphrase is None:
        args.passphrase = input(
            "Enter passphrase for private key encryption: ")

    private_key_pass = args.passphrase.encode()

    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            private_key_pass),
    )
    # b'-----BEGIN ENCRYPTED PRIVATE KEY-----'

    unencrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print("\n")
    print(unencrypted_pem_private_key.decode())
    print("\n\n----------------------------------------\n\n")
    # b'-----BEGIN RSA PRIVATE KEY-----'

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    print(pem_public_key.decode())
    # b'-----BEGIN PUBLIC KEY-----'

    if not os.path.exists("./keys"):
        os.makedirs("./keys")

    private_key_file = open("keys/rsa.pem", "w")
    private_key_file.write(unencrypted_pem_private_key.decode())
    private_key_file.close()

    public_key_file = open("keys/rsa.pub", "w")
    public_key_file.write(pem_public_key.decode())
    public_key_file.close()


if __name__ == "__main__":
    parser = ArgumentParser(description="Generate RSA key pair")
    parser.add_argument(
        "-p", "--passphrase", help="Passphrase for private key encryption"
    )
    args = parser.parse_args()
    main(args)
