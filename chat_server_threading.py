import socket, sys, threading, os
import gnupg

# Simple chat client that allows multiple connections via threads

PORT = 9876 # the port number to run our server on

class ChatServer(threading.Thread):
    
    def __init__(self, port, gpg, clientids, host='localhost'):
        threading.Thread.__init__(self)
        self.gpg = gpg
        if self.gpg.list_keys() == []:              #if keylist is empty
            key_name = input("Username: ")
            key_email = input("Email: ")
            rsa_default = 'RSA'
            key_type = '2048'
            key_information = self.gpg.gen_key_input(name_real=key_name, name_email=key_email, key_type=rsa_default, key_length=key_type, passphrase='my passphrase')
            self.gpg.gen_key(key_information)
            keyids = self.gpg.list_keys()[0]['keyid'] # First Public key on ring
            ascii_armored_public_keys = self.gpg.export_keys(keyids)
            print(ascii_armored_public_keys)            #get the public key that is to be added to the PGP key server

        self.session_key = input("Enter a session passphrase: ")        #prompting the server for a session phrase
        self.clientids = clientids
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {} # current connections
        
        try:
            self.server.bind((self.host, self.port))
        except socket.error:
            print('Bind failed %s' % (socket.error))
            sys.exit()

        self.server.listen(10)
        
    # Not currently used. Ensure sockets are closed on disconnect
    def exit(self):
        self.server.close()

    # Broadcast chat message to all connected clients
    def broadcast (self, conn, username, msg):
        for user in self.connections:
            if (user is not username):
                try:
                    chatmsg_encr = gpg.encrypt(msg, recipients=self.clientids, symmetric="AES256", passphrase=self.session_key)
                    self.connections[user].send(chatmsg_encr.data)
                except:
                    # broken socket connection
                    conn.close()
                    # broken socket, remove it
                    if conn in self.connections:
                        self.connections.remove(conn)

    # Continually listens for messages and broadcasts the messages
    # to all connected users.
    def run_thread(self, username, conn, addr):
        print('Client connected with ' + addr[0] + ':' + str(addr[1]))
        while True:
            try:
                msg_client = conn.recv(1024)
                if len(msg_client) == 0:                #checks to see that client doesnt send empty messages after logging off
                    raise ConnectionError("Connection closed")
                msgD = gpg.decrypt(msg_client, passphrase=self.session_key)     #decrpyting the messages from client using the session passphrase
                displaymsg = msgD.data.decode('utf-8')
                msg = username + ": " + displaymsg
                print("\n", msg)
                self.broadcast(conn, username, msg)
            except Exception as e:
                print("client conn closed : ", username , e)
                msg = username+"(%s, %s) is offline\n" % addr
                self.broadcast(conn, username, msg)
                conn.close() # Close
                del self.connections[username]
                return

    # Start point of server
    def run(self):
        print('Waiting for connections on port %s' % (self.port))
        print("Press CTRL+C to exit from the server anytime..!!")
        # We need to run a loop and create a new thread for each connection
        try:
            while True:
                conn, addr = self.server.accept()
                # First message after connection is username
                encoded_data = conn.recv(1024)
                print(encoded_data)
                data = encoded_data.decode('utf-8')
                client_data = data.split(': ')
                username = client_data[0]           #gives the username of the client
                client_id = client_data[1]          #gives key id of the client key
                if client_id in self.clientids:
                    result = self.gpg.recv_keys('pgp.mit.edu', client_id)   #getting the public key of the client from the PGP server
                else:
                    print("Service Denied, not authorized..!!")
                    break
                if (username not in self.connections):
                    self.connections[username] = conn
                    print(username, "connected")
                    # Need to send the encrypted session passphrase based on the keyid sent with username
                    msgE = self.gpg.encrypt(self.session_key, client_id, always_trust=True)
                    #if (msgE.ok):
                    #    print(msgE.data.decode('utf-8')) 
                    conn.send(msgE.data)
                    thread = threading.Thread(target=self.run_thread, args=(username, conn, addr))
                    thread.daemon = True
                    thread.start()
                else:
                    conn.send(bytes(username+" already exists.  Please restart client.",'utf-8'))
                    conn.close()
        except (KeyboardInterrupt, SystemExit):
            print("Exiting Server..!")
            self.exit()
            sys.exit()


if __name__ == '__main__':
    clientkeyids = ['4ED262C7F567A6AC','B7E0EBE920444A2D']          #list of keyid’s that are authorized to use the chat server
    gpg = gnupg.GPG()
    server = ChatServer(PORT,gpg,clientkeyids)
    # Run the chat server listening on PORT
    server.run()