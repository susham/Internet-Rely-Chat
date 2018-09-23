#####################################################################
#                    Haritha Munagala, Susham Yerabolu              #
#                    CS 594 Internetworking Protocols               #
#                             Spring 2018                           #
#                              IRC Client                           #
#####################################################################

#--------------------------------------------------------------------#
# Python Imports
import socket
import sys
import threading
import select
import CONSTANTS
import json
import os
from Crypto.Cipher import AES
from Crypto import Random
#--------------------------------------------------------------------#

#--------------------------------------------------------------------#
# Encryption Functions for Secure Messaging
#--------------------------------------------------------------------#
# Adds padding to keep data block size == FIXED_BLOCK_SIZE
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
    IV = Random.new().read(16) # randomly generated Initialization vector
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
    # Reads from JSON
    jsonData = json.loads(str(decrypted_data))
    decrypted_data = jsonData["message"]
    return decrypted_data
#-----------------------------------------------------------------------#

#-----------------------------------------------------------------------#
# IRC Client Object
# This class defines an IRC client and what the client is able to do 
# when connected to the server
#-----------------------------------------------------------------------#
class IRCClient():
    # Initializes variables, establishes a connection to the server, and registers the client with the provided name
    def __init__(self,name):
        self.name = name
        # Connect to the server
        self.server_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_connection.connect((CONSTANTS.HOST, CONSTANTS.PORT))
        # Register the client with the provided name
        serverMsg = {}
        serverMsg["command"] = "NN"
        serverMsg["name"] = self.name
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))
        print("You are now connected to Server!")
        self.printCommands()
    

    def printCommands(self):
        f = open('COMMANDS.txt','r')
        message = f.read()
        print(message)
        f.close()
    
    # Prompt format for the client to enter their commands
    def prompt(self):
        print("<" + self.name + "> ", end = '', flush=True)

    # Request a list of rooms from the server
    def listRooms(self):
        serverMsg = {}
        serverMsg["command"] = "LR"
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # Create a room on the IRC server 
    def createRoom(self, roomName):
        serverMsg = {}
        serverMsg["command"] = "CR"
        serverMsg["roomname"] = roomName
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # Join a room on the IRC server
    def joinRoom(self, roomName):
        serverMsg = {}
        serverMsg["command"] = "JR"
        serverMsg["roomname"] = roomName
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # Leave a room on the IRC server
    def leaveRoom(self, roomName):
        serverMsg = {}
        serverMsg["command"] = "LER"
        serverMsg["roomname"] = roomName
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # List all clients connected to the server
    def listClients(self):
        serverMsg = {}
        serverMsg["command"] = "LC"
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # List all clients connected to a room on the IRC Server
    def listRoomClients(self, roomName):
        serverMsg = {}
        serverMsg["command"] = "LRC"
        serverMsg["roomname"] = roomName
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # Send a message to a room on the IRC server
    def msgRoom(self, roomName, message):
        serverMsg = {}
        serverMsg["command"] = "MR"
        serverMsg["roomname"] = roomName
        serverMsg["message"] = message
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # Send a private message to a connected client on the IRC server
    def privateMsg(self, toMessage, message):
        serverMsg = {}
        serverMsg["command"] = "PM"
        serverMsg["target"] = toMessage
        serverMsg["message"] = message
        self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))

    # Send a file to a room 
    def sendFileRoom(self, target, file_name):
        serverMsg = {}
        serverMsg["command"] = "SFR"
        serverMsg["target"] = target
        serverMsg["file_name"] = file_name
        if(os.path.isfile(file_name)):
            serverMsg["file_size"] = os.stat(file_name).st_size
            self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))
        else:
            print("File: '" + file_name + "'' doesn't exist. Please check!")
            self.prompt()

    # Send a file to a connected client on the IRC server
    def sendFilePriv(self, target, file_name):
        serverMsg = {}
        serverMsg["command"] = "SFP"
        serverMsg["target"] = target
        serverMsg["file_name"] = file_name
        if(os.path.isfile(file_name)):
            serverMsg["file_size"] = os.stat(file_name).st_size
            self.server_connection.send(encode_n_encrypt(json.dumps(serverMsg)))
        else:
            print("File: '" + file_name + "'' doesn't exist. Please check!")
            self.prompt()

    # Send the file contents to the server
    def sendFileData(self, file_name):
        # file_data = open(file_name)
        with open(file_name) as file_data:
            read_data = file_data.read(1024)
            while read_data:
                self.server_connection.send(encode_n_encrypt(read_data))
                read_data = file_data.read(1024)
            file_data.close()

    # Receive any incoming file contents from the server
    def receiveFileData(self, message, FILE_NAME, FILE_SIZE):
        with open(self.name + '_' + FILE_NAME, 'wb') as f:
            total_received_data = 0
            while True:
                f.write(message.encode('UTF-8')) # Explicitly encoded to write to file
                total_received_data += len(message.encode('UTF-8'))
                if(total_received_data < FILE_SIZE):
                    message = s.recv(1024)
                    message = decrypt_n_decode(message)
                else:
                    break
            f.close()
        print("File: " + FILE_NAME + " received successfully")

    # The function that is executed once all initialization is complete
    def run(self):
        socket_list = [sys.stdin, self.server_connection]
        # Prompt the client for their command
        self.prompt()

        # File transfer parameters
        FILE_TRANSFER_MODE = False
        FILE_NAME = None
        FILE_SIZE = None

        while True:
            read, write, error = select.select(socket_list, [], [])
            for s in read:
                # Incoming server response
                if s is self.server_connection:
                    # Get server response and display
                    message = s.recv(1024)

                    # No message indicates that the server is down
                    if not message:
                        print("Server Down")
                        sys.exit(1)
                    else:
                        message = decrypt_n_decode(message)
                        # Sends file data when server is ready to recieve
                        if("RECEIVING FILE" in message):
                            self.sendFileData(message.split(" ", 4)[3])

                        # Switch to FILE_TRANSFER_MODE when server is sending a file
                        elif("SENDING FILE" in message):
                            FILE_TRANSFER_MODE = True
                            FILE_NAME = message.split(" ", 10)[8]
                            FILE_SIZE = int(message.split(" ", 10)[9])
                            display_msg = message
                            display_msg = display_msg[:-len(str(FILE_SIZE))]
                            print("\n" + display_msg)

                        # Recieve file data and reset file parameters afterwards
                        elif(FILE_TRANSFER_MODE):
                            self.receiveFileData(message, FILE_NAME, FILE_SIZE)
                            self.prompt()
                            # Resetting the file parameters
                            FILE_TRANSFER_MODE = False
                            FILE_NAME = None
                            FILE_SIZE = None

                        # Print response from server and ask for client input
                        else:
                            print("\n" + message)
                            self.prompt()

                elif s is sys.stdin: # Client sent a command to send to the server
                    # Parse the client command and run the appropriate code for that particular command
                    message = sys.stdin.readline().replace("\n", "")
                    try:
                        command = message.split(" ", 1)[0]

                        # Client wants a list of rooms
                        if command == "LR":
                            self.listRooms()

                        # Client wants to create a room
                        elif command == "CR":
                            roomName = message.split(" ", 1)[1]
                            self.createRoom(roomName)

                        # Client wants to join a room
                        elif command == "JR":
                            roomName = message.split(" ", 1)[1]
                            self.joinRoom(roomName)

                        # Client wants to leave a room
                        elif command == "LR":
                            roomName = message.split(" ", 1)[1]
                            self.leaveRoom(roomName)

                        # Client wants a list of all connected clients
                        elif command == "LC":
                            self.listClients()

                        # Client wants a list of clients in a particular room
                        elif command == "LRC":
                            roomName = message.split(" ", 1)[1]
                            self.listRoomClients(roomName)

                        # Client wants to send a message to a room
                        elif command == "MR":
                            parse = message.split(" ", 2)
                            self.msgRoom(parse[1], parse[2])

                        # Client wants to send a private message
                        elif command == "PM":
                            parse = message.split(" ", 2)
                            self.privateMsg(parse[1], parse[2])

                        # Client wants to send file to a room
                        elif command == "SFR":
                            parse = message.split(" ", 2)
                            self.sendFileRoom(parse[1], parse[2])

                        # Client wants to send file to another client
                        elif command == "SFP":
                            parse = message.split(" ", 2)
                            self.sendFilePriv(parse[1], parse[2])

                        # Client wants to terminate the program
                        elif command == "EXIT":
                            print("Terminating program...")
                            self.server_connection.close()
                            sys.exit(0)
                        
                        # Client wants to know the commands
                        elif command == "HELP":
                            self.printCommands()
                            self.prompt()

                        # Invalid command
                        else:
                            print("Invalid command! Please enter a valid command!")
                            self.prompt()

                    # Few arguments are given the a particular command
                    except IndexError as ie:
                        print("Command received too few arguments! Please try again!")
                        self.prompt()
                        continue

#-----------------------------------------------------------------------#
# Main function
# Asks the client for their username then connects them to the server
#-----------------------------------------------------------------------#
def main():
    name = input("Please enter your name: ")
    client = IRCClient(name)
    client.run()

if __name__ == "__main__":
    main()
