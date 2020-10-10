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


def main():
    s = socket.socket()
    s.connect(("3.126.154.76", 80))

    data = s.recv(1024)
    print(data.decode())

    # for counting how many words did i send to the server
    i = 0

    # looping for each possible sequence
    for option in options:
        words = option.split(' ')
        for word in words:
            i += 1

            # adding \n for each word
            word += "\n"
            print(word)

            # encrypting each word and sending to the server
            arc4 = ARC4('csa-mitm-key')
            cipher = arc4.encrypt(word)
            s.send(cipher)

        response = s.recv(4096)

        # checking if the response is not some crap
        if response != b'\x01:\xa12$\xc1O,A\x82\xee\x08}\x80\x1f\x10T\xc9\x92\xa5_\x1b\xec@\xf3\xdb;\x952\xea8\xf9' and response != b'Welcome! your RC4 key is: csa-mitm-key\n' and response != b'\xee\x08}\x80\x1f\x10T\xc9\x92\xa5_\x1b\xec@\xf3\xdb;\x952\xea8\xf9':
            print(i)
            print(response)
            print(arc4.decrypt(response))
            return response

        # creating a new connection to the server
        s = socket.socket()
        s.connect(("3.126.154.76", 80))
        data = s.recv(1024)
        print(data.decode())

    print(i)


if __name__ == "__main__":
    main()
