from totpy_auth.client import Client
from totpy_auth.server import Server


def main():
    server = Server()
    client = Client(server)
    registration_success = client.register_in_server()

    if registration_success:
        client.generate_totp_secret_in_server_and_register()
        totp_code_valid = client.send_totp_code()

        if totp_code_valid:
            print("-- Starting a session cycle --", end="\n\n")
            # Loop de troca de mensagens cifradas reestabelecendo session key
            while True:
                client.establish_session_key()

                client.send_encrypted_message_to_server()

                server.send_encrypted_message_to_client(client)

                print("-- Chat session completed, starting a new one. --", end="\n\n")
        else:
            print("App: Invalid TOTP code")
    else:
        print("App: Invalid authentication token")
