#####################################################################
#                    Haritha Munagala, Susham Yerabolu              #
#                    CS 594 Internetworking Protocols               #
#                             Spring 2018                           #
#                              IRC Server                           #
#####################################################################

#--------------------------------------------------------------------#
# Python Imports
import socket
import sys
import threading
import select
import CONSTANTS
import json
from Crypto.Cipher import AES
from Crypto import Random
#--------------------------------------------------------------------#

#--------------------------------------------------------------------#
# Encryption Functions for Secure Messaging
#--------------------------------------------------------------------#
# Adds padding to data keep block size = FIXED_BLOCK_SIZE
def add_padding(data, interrupt, pad, block_size):
    new_data = ''.join([data, interrupt])
    new_data_len = len(new_data)
    remaining_len = block_size - new_data_len
    to_pad_len = remaining_len % block_size
    pad_string = pad * to_pad_len
    return ''.join([new_data, pad_string])

# Removes extra padding
def strip_padding(data, interrupt, pad):
    return data.rstrip(pad).rstrip(interrupt)

# Pads, encodes, and then encrypt the data
def encode_n_encrypt(data):
    # converts to JSON
    client_msg = {}
    client_msg["message"] = data
    data = json.dumps(client_msg)

    IV = Random.new().read(16) # Randomly generated Initialization vector
    padded_data = add_padding(data, CONSTANTS.INTERRUPT, CONSTANTS.PAD, CONSTANTS.FIXED_BLOCK_SIZE)
    padded_data = padded_data.encode('UTF-8')
    obj = AES.new(CONSTANTS.KEY, AES.MODE_CFB, IV)
    ciphertext = obj.encrypt(padded_data)
    return IV+ciphertext

# Decrypts, decodes, and strips pads in data
def decrypt_n_decode(data):
    IV = data[:16] # Extracts the Initialization Vector of size 16
    ciphertext = data[16:] # Extracts the ciphertext
    obj = AES.new(CONSTANTS.KEY, AES.MODE_CFB, IV)
    decrypted_padded_data = obj.decrypt(ciphertext)
    decrypted_padded_data = decrypted_padded_data.decode('UTF-8')
    decrypted_data = strip_padding(decrypted_padded_data, CONSTANTS.INTERRUPT, CONSTANTS.PAD)
    return decrypted_data
#--------------------------------------------------------------------#

#--------------------------------------------------------------------#
# IRC Room
# This class defines what an IRC room is. An IRC room contains the room
# name along with a dictionary of the clients that are part of that room
#--------------------------------------------------------------------#
class IRCRoom():
    def __init__(self, name):
        self.name = name #Name of the room
        self.roomClients = {} #Dictionary containing all clients that are part of the room
#--------------------------------------------------------------------#

#--------------------------------------------------------------------#
# IRC Server
# This class defines the IRC server. 
#--------------------------------------------------------------------#
class IRCServer(threading.Thread):
    # Initializes variables and data structures for keeping track of rooms and connected clients
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.lock = threading.Lock()
        self.host = host
        self.port = port
        # Dictionay containing all clients connected to the server. 
        #   Key: Socket Object
        #   Value: Client name associated with the socket object
        self.clients = {}
        #List containing all rooms on the server
        self.rooms = []

    # Remove a client from all rooms they are part of and then from the list of connected clients
    def cleanup(self, socket):
        # Remove person from all rooms
        for room in self.rooms:
            # Go through all clients in a room
            for personSocket in room.roomClients:
                # Remove the client from the room, then check the next room
                if personSocket == socket:
                    del room.roomClients[personSocket]
                    break
            # Notify that the user has left the room
            for personSocket in room.roomClients:
                if personSocket != socket:
                    personSocket.send(encode_n_encrypt("<" + room.name + "> " + self.clients[socket] + " has left!"))

        # Remove client from list of clients
        del self.clients[socket]

    # The function that is executed once initialized is complete
    def run(self):
        # Create and bind socket to host and port
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind((self.host, self.port))
        FILE_TRANSFER_MODE = False
        FILE_NAME = None
        FILE_SIZE = None
        FILE_CLIENT_LIST=[]

        # Check if server socket is in the clients list or not
        self.lock.acquire()
        if("SERVER" in self.clients):
            print("Server is alredy active and running!")
            sys.exit(1)
        else:
            # Add server socket to dictionary
            self.clients[self.serverSocket] = "SERVER"
        self.lock.release()

        self.serverSocket.listen(1)
        while True:
            try:
                read, write, error = select.select(list(self.clients.keys()), [], [])
            except socket.error as msg:
                continue

            for s in read:
                # Server socket is readable so have it listen to incoming client connections
                if s == self.serverSocket:
                    try:
                        clientSocket, clientAddr = self.serverSocket.accept()
                    except socket.error:
                        break
                    # If client is already connected to the server, send an appropriate message
                    if(clientSocket in self.clients):
                        clientSocket.send(encode_n_encrypt("You are already connected to the server!"))
                    else:
                        # Add to list of all connected clients
                        self.lock.acquire()
                        self.clients[clientSocket] = clientSocket
                        self.lock.release()
                else:
                    try:
                        data = s.recv(1024)

                        print("Data Received (Encrypted): " + str(data))
                        if data:
                            print("\nData Received (Decrypted): " + str(decrypt_n_decode(data)))

                        if not data:
                            # Handles the unexpected connection closed by client
                            self.lock.acquire()
                            # Remove client from all rooms and then from list of connected clients
                            client_name = self.clients[s]
                            self.cleanup(s)
                            self.lock.release()
                            s.close()
                            print("Connection closed by client: " + client_name)

                        # Performs file transfer among client via server
                        elif(FILE_TRANSFER_MODE):
                            data = decrypt_n_decode(data)
                            total_received_data = 0

                            # Transfers file data as it is recived to target client(s)
                            while True:
                                # Sending the received file data to target clients
                                for client in FILE_CLIENT_LIST:
                                    client.send(encode_n_encrypt(data))
                                total_received_data += len(data)
                                # Recieves file data fromt the sender client
                                if(total_received_data < FILE_SIZE):
                                    data = s.recv(1024)
                                    data = decrypt_n_decode(data)
                                else:
                                    break

                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> File " + FILE_NAME + " sent succesfully!"))

                            # Resetting the file parameters
                            FILE_TRANSFER_MODE = False
                            FILE_NAME = None
                            FILE_SIZE = None
                            FILE_CLIENT_LIST = []

                        else:
                            data = decrypt_n_decode(data)
                            jsonData = json.loads(str(data))
                            command = jsonData["command"]

                            # Associate client name to socket object
                            if command == "NN":
                                self.lock.acquire()
                                name = jsonData["name"]
                                if name in self.clients.values():
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Name already in use!"))
                                else:
                                    self.clients[s] = jsonData["name"]
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Connected to server under username: " + name))
                                self.lock.release()

                            # Client wants a list of all active rooms
                            elif command == "LR":
                                self.lock.acquire()
                                if self.rooms:
                                    message = ""
                                    for room in self.rooms:
                                        message += "\n\t" + room.name

                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Available Rooms:" + message))
                                else:
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> No avaiable rooms"))
                                self.lock.release()

                            # Client wants to create a room
                            elif command == "CR":
                                allowCreate = True
                                self.lock.acquire()
                                for room in self.rooms:
                                    if jsonData["roomname"] == room.name:
                                        allowCreate = False
                                        s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Room name already taken! Please enter a different room name!"))
                                        break

                                if allowCreate == True:
                                    # Create new room with the given room name
                                    newRoom = IRCRoom(jsonData["roomname"])
                                    # Add the client to the room list
                                    newRoom.roomClients[s] = self.clients[s]
                                    # Add room to list of rooms
                                    self.rooms.append(newRoom)
                                    # Send message to client
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Room created succesfully! You have been added to the room!"))
                                self.lock.release()

                            # Client wants to join a room
                            elif command == "JR":
                                roomExists = False
                                self.lock.acquire()
                                # Add the client to a room if it exists
                                for room in self.rooms:
                                    if jsonData["roomname"] == room.name:
                                        # Check to make sure that user is not already in room:
                                        if s not in room.roomClients:
                                            # Add user to the room if it exists
                                            room.roomClients[s] = self.clients[s]

                                            # Notify client that they have joined the room succesfully
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> You have successfully joined the room!"))

                                             # Notify other members in the room about new client joining
                                            for userSocket in room.roomClients:
                                                if userSocket != s:
                                                    userSocket.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> " + self.clients[s] + " has joined the room " + room.name + "!"))
                                        else:
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> You are already in the room!"))
                                        roomExists = True
                                        break

                                # Notify client that the room doesn't exist!
                                if roomExists == False:
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Unable to join room! The room may not exist. Try creating a room with the CREATEROOM [roomname] command"))
                                self.lock.release()

                            # Client wants to leave a room
                            elif command == "LER":
                                self.lock.acquire()
                                room_found = False
                                # Find the room in the list of rooms
                                for room in self.rooms:
                                    if jsonData["roomname"] == room.name:
                                        room_found = True
                                        # Attempt to remove client from the room
                                        try:
                                            del room.roomClients[s]
                                            # Inform client that they have left the room successfully
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> You have successfully left the room!"))

                                            # If there are no more clients in the room, delete the room
                                            if len(room.roomClients) == 0:
                                                self.rooms.remove(room)
                                            else:
                                                # Notify other in room that the user has left the room
                                                for personSocket in room.roomClients:
                                                    personSocket.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> " + self.clients[s] + " has left the room " + room.name + "!"))

                                            break
                                        except KeyError: # Client is not in the room!
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Unable to leave room!"))
                                            break
                                if (not room_found):
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> No room exists with name: " + jsonData["roomname"]))

                                self.lock.release()

                            # Client wants a list of clients connected to the server
                            elif command == "LC":
                                self.lock.acquire()
                                if self.clients:
                                    message = ""
                                    for personSocket, person in self.clients.items():
                                        if personSocket != self.serverSocket:
                                            message += "\n\t" + person

                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Connected Clients:" + message))
                                else:
                                    # You are the only connected client on server
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> You are all alone! Go invite more people to join!!"))
                                self.lock.release()

                            # Client wants a list of clients in the room
                            elif command == "LRC":
                                self.lock.acquire()
                                room = jsonData["roomname"]
                                success = False
                                if self.rooms:
                                    message = ""
                                    # Find the room the get list of clients
                                    for r in self.rooms:
                                        if room == r.name:
                                            # Get the list of clients in the room
                                            for personSocket, person in r.roomClients.items():
                                                if personSocket != self.serverSocket:
                                                    message += "\n\t" + person
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Connected Clients in " + room + ":" + message))
                                            success = True
                                            break
                                    if success == False:
                                        s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Nobody in the room"))
                                else:
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> No rooms exist!"))
                                self.lock.release()

                            # Client wants to send a message to a room
                            elif command == "MR":
                                self.lock.acquire()

                                room = jsonData["roomname"]
                                message = jsonData["message"]
                                success = False

                                # Search through rooms list
                                if self.rooms:
                                    for r in self.rooms:
                                        # Found room
                                        if room == r.name:
                                            # Check to make sure that the client is part of the room first
                                            if s in r.roomClients:
                                                # Send messages to all others in the room
                                                for userSocket in r.roomClients.keys():
                                                    if userSocket != s:
                                                        userSocket.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> " + self.clients[s] + " in " + r.name + " says: " + message))
                                                success = True
                                                break
                                # Send client a message indicating that the room does not exist or they are not part of the indicated room
                                if success == False:
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Unable to send message! The room does not exist or you are not part of the room!") )
                                else:
                                     s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Message sent to room") )
                                self.lock.release()

                            # Client wants to send a private message to another client
                            elif command == "PM":
                                self.lock.acquire()
                                target = jsonData["target"]
                                message = jsonData["message"]
                                if self.clients:
                                    for personSocket, person in self.clients.items():
                                        if personSocket != self.serverSocket and person == target and personSocket != s:
                                            personSocket.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> " + self.clients[s] + " sent a message to you: " + message))
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Private message sent to " + person))
                                        if person == target and personSocket == s:
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Cannot send message to yourself!"))
                                            break
                                else:
                                    # You are the only connected client on server
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Unable to send private message! Nobody else is online!"))
                                self.lock.release()

                            # Client wants to send a file to a room
                            elif command == "SFR":
                                self.lock.acquire()
                                target = jsonData["target"]
                                FILE_NAME = jsonData["file_name"]
                                FILE_SIZE = jsonData["file_size"]
                                FILE_TRANSFER_MODE = True
                                FILE_CLIENT_LIST = []
                                success = False

                                if self.rooms:
                                    for r in self.rooms:
                                        # Found room
                                        if target == r.name:
                                            # Check to make sure that the client is part of the room first
                                            if s in r.roomClients:
                                                # Send messages to all others in the room
                                                for userSocket in r.roomClients.keys():
                                                    if userSocket != s:
                                                        userSocket.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> " + self.clients[s] + " in room " + target + " IS SENDING FILE: " + FILE_NAME + " " + str(FILE_SIZE)))
                                                        FILE_CLIENT_LIST.append(userSocket)
                                                success = True
                                                break

                                # Send client a message indicating that the room does not exist or they are not part of the indicated room
                                if success == False:
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Unable to send file! The room does not exist or you are not part of the room!") )
                                # Send client message to start the file transfer
                                else:
                                    s.send(encode_n_encrypt(("<" + self.clients[self.serverSocket] + "> RECEIVING FILE: " + FILE_NAME)))

                                self.lock.release()

                            # Client wants to send a file to another client
                            elif command == "SFP":
                                self.lock.acquire()
                                target = jsonData["target"]
                                FILE_NAME = jsonData["file_name"]
                                FILE_SIZE = jsonData["file_size"]
                                FILE_TRANSFER_MODE = True
                                FILE_CLIENT_LIST = []
                                success = False

                                if self.clients:
                                    for personSocket, person in self.clients.items():
                                        if personSocket != self.serverSocket and person == target and personSocket != s:
                                            FILE_CLIENT_LIST.append(personSocket)
                                            s.send(encode_n_encrypt(("<" + self.clients[self.serverSocket] + "> RECEIVING FILE: " + FILE_NAME)))
                                            personSocket.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> " + self.clients[s] + " (in private mode) is SENDING FILE: " + FILE_NAME + " " + str(FILE_SIZE)))
                                            success = True
                                        if person == target and personSocket == s:
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Cannot send file to yourself!"))
                                            success = True
                                            break
                                    if success == False:
                                            s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Unable to send private file! Nobody is online with name: " + target))
                                else:
                                    # You are the only connected client on server
                                    s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Unable to send private file! Nobody else is online!"))
                                self.lock.release()

                            # Client send an invalid command
                            else:
                                s.send(encode_n_encrypt("<" + self.clients[self.serverSocket] + "> Received invalid command! Please enter a valid command!"))

                    except Exception as e:
                        # Disconnect client from server and remove from connected clients list
                        print("ERROR: " + str(e))
                        s.close()

                        self.lock.acquire()
                        self.cleanup(s)
                        self.lock.release()
                        continue

        self.serverSocket.close() #Technically, unreachable code.
#--------------------------------------------------------------------#

#--------------------------------------------------------------------#
# Main function
# This function creates an IRCServer object and starts the server to 
# listen for incoming connections
#--------------------------------------------------------------------#
def main():
    server = IRCServer(CONSTANTS.HOST, CONSTANTS.PORT)
    server.start()

if __name__ == "__main__":
    main()
