import socket
from arc4 import ARC4

options = ['organization administration I as I environmental about accept ability according',
           'particularly administration I as I environmental about accept ability according',
           'organization administration a as I environmental about accept ability according',
           'particularly administration a as I environmental about accept ability according',
           'organization administration I at I environmental about accept ability according',
           'particularly administration I at I environmental about accept ability according',
           'organization administration a at I environmental about accept ability according',
           'particularly administration a at I environmental about accept ability according',
           'organization administration I be I environmental about accept ability according',
           'particularly administration I be I environmental about accept ability according',
           'organization administration a be I environmental about accept ability according',
           'particularly administration a be I environmental about accept ability according',
           'organization administration I as a environmental about accept ability according',
           'particularly administration I as a environmental about accept ability according',
           'organization administration a as a environmental about accept ability according',
           'particularly administration a as a environmental about accept ability according',
           'organization administration I at a environmental about accept ability according',
           'particularly administration I at a environmental about accept ability according',
           'organization administration a at a environmental about accept ability according',
           'particularly administration a at a environmental about accept ability according',
           'organization administration I be a environmental about accept ability according',
           'particularly administration I be a environmental about accept ability according',
           'organization administration a be a environmental about accept ability according',
           'particularly administration a be a environmental about accept ability according',
           'organization administration I as I environmental about across ability according',
           'particularly administration I as I environmental about across ability according',
           'organization administration a as I environmental about across ability according',
           'particularly administration a as I environmental about across ability according',
           'organization administration I at I environmental about across ability according',
           'particularly administration I at I environmental about across ability according',
           'organization administration a at I environmental about across ability according',
           'particularly administration a at I environmental about across ability according',
           'organization administration I be I environmental about across ability according',
           'particularly administration I be I environmental about across ability according',
           'organization administration a be I environmental about across ability according',
           'particularly administration a be I environmental about across ability according',
           'organization administration I as a environmental about across ability according',
           'particularly administration I as a environmental about across ability according',
           'organization administration a as a environmental about across ability according',
           'particularly administration a as a environmental about across ability according',
           'organization administration I at a environmental about across ability according',
           'particularly administration I at a environmental about across ability according',
           'organization administration a at a environmental about across ability according',
           'particularly administration a at a environmental about across ability according',
           'organization administration I be a environmental about across ability according',
           'particularly administration I be a environmental about across ability according',
           'organization administration a be a environmental about across ability according',
           'particularly administration a be a environmental about across ability according']


def main(option):
    arc4 = ARC4('csa-mitm-key')

    # looping for each possible sequence
    s = socket.socket()
    s.connect(("3.126.154.76", 80))
    data = s.recv(1024)
    data1 = s.recv(1024)

    print('data1 is ' + str(arc4.decrypt(data1)))

    words = option.split(' ')
    for word in words:
        # adding \n for each word
        word += "\n"

        # encrypting each word and sending to the server
        cipher = arc4.encrypt(word)
        s.send(cipher)

    response = s.recv(1024)

    # checking if the response is not some crap
    if response != b'\x01:\xa12$\xc1O,A\x82\xee\x08}\x80\x1f\x10T\xc9\x92\xa5_\x1b\xec@\xf3\xdb;\x952\xea8\xf9' and response != b'Welcome! your RC4 key is: csa-mitm-key\n' and response != b'\xee\x08}\x80\x1f\x10T\xc9\x92\xa5_\x1b\xec@\xf3\xdb;\x952\xea8\xf9':
        message = arc4.decrypt(response)
        s.close()
        if message.startswith(b'CSA'):
            print('The flag is ' + str(message))
            quit(1)


if __name__ == "__main__":
    for option in options:
        main(option)
