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

    for option in options:
        try:
            i = 0
            words = option.split(' ')
            for word in words:
                i += 1
                word += "\n"
                print(word)
                arc4 = ARC4('csa-mitm-key')
                cipher = arc4.encrypt(word)
                s.send(cipher)

                if i % 10 == 0 and i != 0 and i != 1:
                    response = s.recv(4096)
                    if response != b'\x01:\xa12$\xc1O,A\x82\xee\x08}\x80\x1f\x10T\xc9\x92\xa5_\x1b\xec@\xf3\xdb;\x952\xea8\xf9' and response != b'Welcome! your RC4 key is: csa-mitm-key\n':
                        print(response)

        except socket.error:
            print("Exception")
            s = socket.socket()
            s.connect(("3.126.154.76", 80))

    print(i)


if __name__ == "__main__":
    main()
