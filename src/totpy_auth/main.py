import logging
import sys

from totpy_auth.client import Client
from totpy_auth.server import Server

LOOP_SESSION = False
log = logging.getLogger("totpy_auth")


def main():
    server = Server()
    client = Client(server)
    registration_success = client.register_in_server()

    if registration_success:
        totp_code_valid = True
        while totp_code_valid:
            log.info("-- Starting a session cycle --")
            totp_code_valid = client.send_2fa()

            if totp_code_valid:
                log.info("-- Login 2fa success --")

                client.send_encrypted_message_to_server()
                server.send_encrypted_message_to_client(
                    client.username, client.receive_and_decrypt_message
                )

            if not LOOP_SESSION:
                log.info("-- Chat session completed, exiting app --")
                sys.exit(0)

            log.info("-- Chat session completed, starting a new one. --")
        else:
            log.warning("App: Invalid TOTP code")
    else:
        log.warning("App: Client registration failed, closing app!")
