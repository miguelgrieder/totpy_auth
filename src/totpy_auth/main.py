import sys

from totpy_auth.client import Client
from totpy_auth.server import Server

LOOP_SESSION = False


def main():
    server = Server()
    client = Client(server)
    registration_success = client.register_in_server()

    if registration_success:
        totp_code_valid = True
        while totp_code_valid:
            print("-- Starting a session cycle --", end="\n\n")
            totp_code_valid = client.send_2fa()

            if totp_code_valid:
                client.send_encrypted_message_to_server()
                server.send_encrypted_message_to_client(client)

            if not LOOP_SESSION:
                print("-- Chat session completed, exiting app --", end="\n\n")
                sys.exit(0)

            print("-- Chat session completed, starting a new one. --", end="\n\n")
        else:
            print("App: Invalid TOTP code")
    else:
        print("App: Client registration failed, closing app!")
