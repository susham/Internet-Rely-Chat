#####################################################################
#                    Haritha Munagala, Susham Yerabolu              #
#                    CS 594 Internetworking Protocols               #
#                             Spring 2018                           #
#####################################################################

#defines constants here
HOST='127.0.0.1'       # Local Host
#HOST='162.243.139.14' # Cloud Host
PORT=8080

# required parameters for AES encryption
KEY='a1b4c6d1efgh5678'# key shared between server and client only
INTERRUPT = u'\u0001' # Interrupt to detect padding start
PAD = u'\u0000'       # Padding (zero)
FIXED_BLOCK_SIZE = 16 # Must be 16 for Python AES.
