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

    def _dh_ratchet(self, name: str, header: dict = None) -> None:
        """
        Perform a DH ratchet step.
        
        Inputs:
            name: username of the other party
            header: message header (only needed for receiving)
        """
        conn = self.conns[name]
        
        # Receiving case
        if header is not None:
            # Store their new DH public key
            conn["DHr"] = header["dh_public"]
            
            # Derive new root key and receiving chain key
            dh_output = compute_dh(conn["DHs"]["private"], conn["DHr"])
            conn["RK"], conn["CKr"] = hkdf(conn["RK"], dh_output, "RACHET-STEP")
            
            # Generate a new DH key pair
            conn["DHs"] = generate_eg()
            
            # Compute DH with our new key and their key
            dh_output = compute_dh(conn["DHs"]["private"], conn["DHr"])
            conn["RK"], conn["CKs"] = hkdf(conn["RK"], dh_output, "RACHET-STEP")
            
            # Reset message counters
            conn["PN"] = conn["Ns"]
            conn["Ns"] = 0
            conn["Nr"] = 0
            
        # Sending case (no header)
        else:
            # Only perform the DH ratchet if we've received at least one message from them
            if conn["DHr"] is not None:
                # Generate a new DH key pair
                conn["DHs"] = generate_eg()
                
                # Compute DH with our new key and their key
                dh_output = compute_dh(conn["DHs"]["private"], conn["DHr"])
                conn["RK"], conn["CKs"] = hkdf(conn["RK"], dh_output, "RACHET-STEP")
                
                # Reset message counters
                conn["PN"] = conn["Ns"]
                conn["Ns"] = 0
    
    def _symmetric_ratchet_sending(self, name: str) -> bytes:
        """
        Perform a symmetric ratchet step for sending.
        
        Inputs:
            name: username of the other party
            
        Returns:
            message_key: the key to use for encrypting the next message
        """
        conn = self.conns[name]
        
        # Ratchet the sending chain to get the next message key
        message_key = hmac_to_aes_key(conn["CKs"], str(conn["Ns"]))
        conn["CKs"] = hmac_to_hmac_key(conn["CKs"], "CHAIN-KEY-SENDING")
        conn["Ns"] += 1
        
        return message_key
    
    def _symmetric_ratchet_receiving(self, name: str, msg_index: int) -> bytes:
        """
        Perform a symmetric ratchet step for receiving.
        
        Inputs:
            name: username of the other party
            msg_index: the index of the message to receive
            
        Returns:
            message_key: the key to use for decrypting the message
        """
        conn = self.conns[name]
        
        # Check for replay attacks
        if msg_index in conn["received_msgs"]:
            raise Exception("Message replay detected!")
        
        # Add to received messages set
        conn["received_msgs"].add(msg_index)
        
        # Ratchet the receiving chain to get the message key
        ckr = conn["CKr"]
        for i in range(msg_index - conn["Nr"]):
            message_key = hmac_to_aes_key(ckr, str(conn["Nr"] + i))
            ckr = hmac_to_hmac_key(ckr, "CHAIN-KEY-RECEIVING")
        
        # Update the receiving chain key
        conn["CKr"] = ckr
        conn["Nr"] = msg_index + 1
        
        return message_key



    def generate_certificate(self, username: str) -> dict:
        """
        Generate a certificate to be stored with the certificate authority.
        The certificate must contain the field "username".

        Inputs:
            username: str

        Returns:
            certificate: dict
        """
        
        # store the username
        self.username = username
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
            dh_output = compute_dh(self.conns[name]["DH_pair"]["private"], self.certs[name])
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

        '''
        From the spec:
        The header must include the fields “v_gov” and “c_gov” which
        denote the outputs (v, c) of the ElGamal public key encryption. You will also need to pass an
        “iv_gov” containing the IV used toencrypt the message key forthe government and a “receiver_iv”
        containing the IV used to encrypt the message for the receiver.
        '''
        # generate 2 IVs for the GCM encryption, one for the receiver and for the government
        iv_receiver = gen_random_salt()
        iv_gov = gen_random_salt()

        # new ElGamal pair for the government
        dh_gov = generate_eg()
        # Encrypt the sending chain key for the government
        shared_secret_gov = compute_dh(dh_gov["private"], self.gov_public_key)
        shared_secret_gov = hmac_to_aes_key(shared_secret_gov, gov_encryption_data_str)
        gov_ciphertext_info = encrypt_with_gcm(shared_secret_gov, message_key, iv_gov)

        # Add the government's info to the header
        header["v_gov"] = dh_gov["public"]
        header["c_gov"] = gov_ciphertext_info
        header["iv_gov"] = iv_gov
        header["receiver_iv"] = iv_receiver

        # Encrypt the message
        ciphertext_info = encrypt_with_gcm(message_key, plaintext, iv_receiver, str(header))

        # return the header and the ciphertext
        return header, ciphertext_info




    def receive_message(self, name: str, message: tuple[dict, tuple[bytes, bytes]]) -> str:
        """
        Decrypt a message received from another user.

        Inputs:
            name: str
            message: tuple(dict, tuple(bytes, bytes))

        Returns:
            plaintext: str
        """
        header, ciphertext = message
    
        if header["receiver"] != self.username:
            raise Exception("Message not intended for this recipient")
        
        # Initialize the connection if this is the first message
        first_message = name not in self.conns
        if first_message:
            self.conns[name] = {
                "DH_pair": self.identity_key_pair,
                "DH_receiver": header["dh_public"],
                "RK" : None, # root key
                "CKs" : None, # chain key sending
                "CKr" : None, # chain key receiving
                "Ns" : 0, # message number sending
                "Nr" : 0, # message number receiving
                "PNs" : 0, # # Number of messages in previous sending chain
                "received_messages" : set() # set of received messages to prevent replay attacks
            }

        conn = self.conns[name]

        # Check if this is the first message or if the DH ratchet needs to be updated
        if conn["DH_receiver"] is None or header["dh_public"] != conn["DH_receiver"]:
            # Perform a DH ratchet step

            # store their new public key
            conn["DH_receiver"] = header["dh_public"]

            # Derive new root key and receiving chain key
            dh_output = compute_dh(conn["DH_pair"]["private"], conn["DH_receiver"])
            conn["RK"], conn["CKr"] = hkdf(conn["RK"], dh_output, "RACHET-STEP")

            # Generate a new DH key pair for future sending
            conn["DH_pair"] = generate_eg()
            dh_output = compute_dh(conn["DH_pair"]["private"], conn["DH_receiver"])
            conn["RK"], conn["CKs"] = hkdf(conn["RK"], dh_output, "RACHET-STEP")

            # Reset message counters
            conn["PNs"] = conn["Ns"]
            conn["Ns"] = 0
            conn["Nr"] = 0
        
        # Generate the message key
        if header["message_number"] in conn["received_messages"]:
            raise Exception("Message replay detected!")
        
        conn["received_messages"].add(header["message_number"])

        # Ratchet the receiving chain to get the message key
        ckr = conn["CKr"]
        for i in range(header["message_number"] - conn["Nr"]):
            message_key = hmac_to_aes_key(ckr, str(conn["Nr"] + i))
            ckr = hmac_to_hmac_key(ckr, "CHAIN-KEY-RECEIVING")

        # Update the receiving chain key
        conn["CKr"] = ckr
        conn["Nr"] = header["message_number"] + 1

        # Decrypt the message
        plaintext = decrypt_with_gcm(message_key, ciphertext, header["receiver_iv"], str(header))

        return plaintext
    











        # if first_message:
        #     self._initialize_ratchet(name, False)
        
        # conn = self.conns[name]
        
        # # Special handling for the first message
        # if first_message:
        #     # Use our identity key to derive the initial root key
        #     conn["DHr"] = header["dh_public"]
        #     shared_secret = compute_dh(self.identity_key_pair["private"], conn["DHr"])
        #     conn["RK"] = shared_secret
            
        #     # Derive the initial receiving chain key
        #     dh_output = compute_dh(self.identity_key_pair["private"], conn["DHr"])
        #     conn["RK"], conn["CKr"] = hkdf(conn["RK"], dh_output, "INITIAL-RECEIVING")
            
        #     # Then perform the standard DH ratchet step to prepare for future messages
        #     self._dh_ratchet(name, header)
        
        # # Normal handling for subsequent messages
        # elif conn["DHr"] is None or header["dh_public"] != conn["DHr"]:
        #     # We need to perform a DH ratchet
        #     self._dh_ratchet(name, header)
        
        # # Generate the message key
        # message_key = self._symmetric_ratchet_receiving(name, header["ns"])
        
        # # Decrypt the message
        # plaintext = decrypt_with_gcm(message_key, ciphertext, header["receiver_iv"], str(header))
        
        # return plaintext