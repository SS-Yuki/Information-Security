from socket import socket, AF_INET, SOCK_STREAM
import sys, os
sys.path.append("../../ns")
from helpers import *

def extract():
    """() -> NoneType
    Opens the public key infrastructure server to extract RSA public keys.
    The public keys must have already been in the server's folder.
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((PKI_HOST, PKI_PORT))
        sock.listen()
        
        while True:
            conn, addr = sock.accept()
            with conn:
                print('PKI: connection from address', addr)
                # A, B --->  
                # <--- {K_PB, B}(K_PA)
                # WRITE YOUR CODE HERE!
                data = conn.recv(1024)
                data = data.decode()
                sender, target = data.split(",")
                
                sender_public_key_file = f"{sender}.asc"
                target_public_key_file = f"{target}.asc"
                
                with open(sender_public_key_file, "rb") as file:
                    sender_public_key = file.read()
                    sender_public_key_str = sender_public_key.decode('utf-8')

                with open(target_public_key_file, "rb") as file:
                    target_public_key = file.read()
                    target_public_key_str = target_public_key.decode('utf-8')

                response = rsa.big_encrypt(rsa.import_key(sender_public_key), f"{target_public_key_str},{target}")

                conn.sendall(b','.join(response))

            


if __name__ == "__main__":
    print("PKI: I am the Public Key Infrastructure Server!")
    print("PKI: listening for a key to be extracted")
    extract()
