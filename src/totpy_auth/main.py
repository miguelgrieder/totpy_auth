from totpy_auth.client import Client
from totpy_auth.server import Server


def main():
    server = Server()
    client = Client(server)
    token_valid = client.send_authentication_info()

    if token_valid:
        client.auth_totp_secret()
        totp_code_valid = client.send_totp_code()

        if totp_code_valid:
            print("-- Starting a session cycle --", end="\n\n")
            # Loop de troca de mensagens cifradas reestabelecendo session key
            while True:
                client.establish_session_key()

                message_to_server = input("Enter message to send to server: ").encode()
                encrypted_message = client.send_message_with_encryption(message_to_server)

                message_to_client = input("Enter message to send to client: ").encode()
                encrypted_message = server.send_message_with_encryption(message_to_client, client)

                print("-- Chat session completed, starting a new one. --", end="\n\n")
        else:
            print("Invalid TOTP code")
    else:
        print("Invalid authentication token")


if __name__ == "__main__":
    main()
