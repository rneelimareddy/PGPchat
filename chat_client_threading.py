import socket, sys, threading , os
import select
import gnupg

PORT = 9876
SERVER_KEY_ID = 'E26731AE86CCB653'              #assuming client already knows the server

class ChatClient(threading.Thread):

    def __init__(self, port, gpg, host='localhost'):
        threading.Thread.__init__(self)
        self.gpg = gpg

        # Create public/private key if doesn't exist
        if self.gpg.list_keys() == []:          #if key ring is not empty
            key_name = input("Username: ")
            key_email = input("Email: ")
            rsa_default = 'RSA'
            key_type = '2048'
            key_information = self.gpg.gen_key_input(name_real=key_name, name_email=key_email, key_type=rsa_default, key_length=key_type, passphrase='my passphrase')
            key = self.gpg.gen_key(key_information)
            print("Key is :" ,key)
            print("Public Key : ", self.gpg.list_keys())
            print("Private Key : ", self.gpg.list_keys(True))

            keyids = self.gpg.list_keys()[0]['keyid'] # First Public key on ring
            ascii_armored_public_keys = self.gpg.export_keys(keyids)
            print(ascii_armored_public_keys)
        
        result = self.gpg.recv_keys('pgp.mit.edu', SERVER_KEY_ID)

        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, port))

    def send_message(self, msg):
        # Encrypt chat messages in this method
        msgE = gpg.encrypt(msg, recipients=[SERVER_KEY_ID], symmetric="AES256",passphrase=self.session_phrase) # encrypting the messages using the session passphrase shared by the server
        self.socket.send(msgE.data)

    def ReceiveMessage(self):
        # Decrypt chat messages in this method
        while(True):
            data = self.socket.recv(1024)
            if data:
                decrypted_chat = gpg.decrypt(data, passphrase=self.session_phrase)      #descrypting the data
                msg = decrypted_chat.data.decode('utf-8')
                print("\n",msg)

    def run(self):
        print("Starting Client")

        # Currently only sends the username
        self.username = input("Username: ")
        keyid = self.gpg.list_keys()[0]['keyid']
        data = bytes((self.username+": "+keyid), 'utf-8')
        self.socket.send(data)              #sending both username and key id to the server

        # Need to get session passphrase
        msgE_session = self.socket.recv(1024)       #receiving the session passphrase from the server
        if len(msgE_session) == 0:
            print("Permission Denied..!! Not an authorised access")
            exit(0)
        msgD_session = self.gpg.decrypt(msgE_session, passphrase = 'my passphrase') # Automatically figures out key to use
        #print("msgD",msgD_session)
        if (msgD_session.ok):
            self.session_phrase = msgD_session.data.decode('utf-8')
        print("Session Passphrase: ",self.session_phrase) # Prints the decrypted data

        # Starts thread to listen for data
        rec_thread = threading.Thread(target=self.ReceiveMessage)
        rec_thread.setDaemon(True)
        rec_thread.start()
        
        while(True):
            msg = input("\n Enter a msg : ")
            if msg == "exit":                   #client logging off by typing exit 
                print("Logging off")
                self.socket.close()
                sys.exit()
            self.send_message(msg)
        
if __name__ == '__main__': 
    key_home = sys.argv[1]              #getting key_home path as a command line argument to check multiclient
    #key_home = '/Users/neelimareddy/.gnupgclient'
    gpg = gnupg.GPG(gnupghome=key_home)   #creating gpg object
    client = ChatClient(PORT,gpg)
    client.start() # This start run()
