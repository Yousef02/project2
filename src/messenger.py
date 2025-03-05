###############################################################################
# CS 255
# 1/12/25
# 
# messenger.py
# ______________
# Please implement the functions below according to the assignment spec
###############################################################################
from lib import (
    gen_random_salt,
    generate_eg,
    compute_dh,
    verify_with_ecdsa,
    hmac_to_aes_key,
    hmac_to_hmac_key,
    hkdf,
    encrypt_with_gcm,
    decrypt_with_gcm,
    gov_encryption_data_str
)

class MessengerClient:
    def __init__(self, cert_authority_public_key: bytes, gov_public_key: bytes):
        """
        The certificate authority DSA public key is used to
        verify the authenticity and integrity of certificates
        of other users (see handout and receive_certificate)
        """
        # Feel free to store data as needed in the objects below
        # and modify their structure as you see fit.
        self.ca_public_key = cert_authority_public_key
        self.gov_public_key = gov_public_key
        self.conns = {}  # data for each active connection
        self.certs = {}  # certificates of other users
        
        # store our own identity key pair
        self.identity_key_pair = generate_eg()
        self.username = None



    def generate_certificate(self, username: str) -> dict:
        """
        Generate a certificate to be stored with the certificate authority.
        The certificate must contain the field "username".

        Inputs:
            username: str

        Returns:
            certificate: dict
        """
        
        # Generate the necessary ElGamal key pair for key exchanges. Public keys are are placed into a certificate to send to other clients.
        certificate = {
            "username": username,
            "public_key": self.identity_key_pair["public"]
        }
        return certificate
    


    def receive_certificate(self, certificate: dict, signature: bytes) -> None:
        """
        Receive and store another user's certificate.

        Inputs:
            certificate: dict
            signature: bytes

        Returns:
            None
        """
        # check the signature of the certificate against the CA public key
        if not verify_with_ecdsa(self.ca_public_key, str(certificate), signature):
            # throw an exception if the signature is invalid
            raise Exception("Invalid signature")
        # store the certificate
        self.certs[certificate["username"]] = certificate["public_key"]
        return
    

    def establish_connection(self, name: str, as_initiator: bool) -> None:
        """
        Establish a connection with another user.

        Inputs:
            name: str
            as_initiator: bool

        Returns:
            None
        """
        # Generate the necessary double ratchet keys according to the Signal protocol
        if name not in self.conns:
            # Generate the necessary double ratchet keys according to the Signal protocol
            self.conns[name] = {
                "DH_pair": generate_eg(),
                "DH_receiver": None,
                "RK" : None, # root key
                "CKs" : None, # chain key sending
                "CKr" : None, # chain key receiving
                "Ns" : 0, # message number sending
                "Nr" : 0, # message number receiving
                "PNs" : 0, # # Number of messages in previous sending chain
                "received_messages" : set() # set of received messages to prevent replay attacks
            }
        # If we are the initiator, we do the computation of the initial root key
        if as_initiator:
            # Compute the shared secret
            shared_secret = compute_dh(self.identity_key_pair["private"], self.certs[name])
            # Compute the root key
            self.conns[name]["RK"] = shared_secret

        return
        


    def send_message(self, name: str, plaintext: str) -> tuple[dict, tuple[bytes, bytes]]:
        """
        Generate the message to be sent to another user.

        Inputs:
            name: str
            plaintext: str

        Returns:
            (header, ciphertext): tuple(dict, tuple(bytes, bytes))
        """
        # If we have not already established a connection with the user, we need to do so.
        # setup the session by generating the necessary double ratchet keys according to the Signal protocol
        if name not in self.conns:
            self.establish_connection(name, True)

        # Generate the necessary double ratchet keys according to the Signal protocol
        # Check if we need to set up the initial sending chain
        if self.conns[name]["CKs"] is None:
            # Derive initial chain keys
            dh_output = compute_dh(self.conns[name]["DHs"]["private"], self.certs[name])
            self.conns[name]["RK"], self.conns[name]["CKs"] = hkdf(self.conns[name]["RK"], dh_output, "INITIAL-SENDING")

        
        # Generate the necessary double ratchet keys according to the Signal protocol
        # use hmac_to_aes_key to generate the sending_key from the chain key and then update the chain key using hmac_to_hmac_key
        conn = self.conns[name]
        message_key = hmac_to_aes_key(conn["CKs"], str(conn["Ns"]))
        conn["CKs"] = hmac_to_hmac_key(conn["CKs"], "CHAIN_KEY_SEND")
        conn["Ns"] += 1

        # now, we craft the header with the data needed for the receiver to derive the new message key
        header = {
            "dh_public": conn["DH_pair"]["public"],
            "message_number": conn["Ns"] - 1, # the - 1 is because we increment the message number before sending the message
            "previous_message_number": conn["PNs"],
            "sender": self.username,
            "receiver": name
        }

        # generate 2 IVs for the GCM encryption, one for the receiver and for the government
        iv_receiver = gen_random_salt()
        iv_gov = gen_random_salt()

        # new ElGamal pair for the government









        





        # header = {}
        # ciphertext = ""
        # return header, ciphertext


    def receive_message(self, name: str, message: tuple[dict, tuple[bytes, bytes]]) -> str:
        """
        Decrypt a message received from another user.

        Inputs:
            name: str
            message: tuple(dict, tuple(bytes, bytes))

        Returns:
            plaintext: str
        """
        raise NotImplementedError("not implemented!")
        header, ciphertext = message
        plaintext = ""
        return plaintext