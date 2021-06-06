from alice import AliceTlsSession
import sys
import base64
import socket

password_share = b't^QV6p8dX25J67DC#x@2bBeY'

def testSMTPSession():
    f = open("email", "rb")
    email = f.read()

    bob_port = int(sys.argv[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = socket.gethostbyname("smtp.gmail.com")
    sock.connect((ip, 587))
    print(f"Connected to {ip}")
    res = sock.recv(128)
    print(res)
    ehlo = b'EHLO mail.google.com\r\n'
    sock.send(ehlo)
    res = sock.recv(512)
    print(res.split(b'\r\n'))
    sock.send(b'STARTTLS\r\n')
    print(sock.recv(512))

    tls_sesh = AliceTlsSession("smtp.gmail.com", serv_port=587, bob_port=bob_port, logging=True)
    tls_sesh.connectToBob()
    tls_sesh.serv_sock = sock

    tls_sesh.handshake()

    tls_sesh.send(ehlo)
    print(tls_sesh.recv_response().split(b'\r\n'))
    tls_sesh.send(b'AUTH LOGIN\r\n')
    print("AUTH LOGIN")
    print(tls_sesh.recv_response())
    username = base64.b64encode(b'mpcemailtest@gmail.com') + b'\r\n'
    print("USERNAME")
    password = base64.b64encode(password_share) + b'\r\n'
    tls_sesh.send(username)
    print(tls_sesh.recv_response())
    print("PASSWORD")
    tls_sesh.sendPassword(password)
    print(tls_sesh.recv_response())
    tls_sesh.send(b'MAIL FROM:<mpcemailtest@gmail.com>\r\n')
    print(tls_sesh.recv_response())
    tls_sesh.send(b'RCPT TO:<littler@oregonstate.edu>\r\n')
    print(tls_sesh.recv_response())
    tls_sesh.send(b'DATA\r\n')
    print(tls_sesh.recv_response())
    tls_sesh.send(email)
    print(tls_sesh.recv_response())
    tls_sesh.send(b'QUIT\r\n')
    print(tls_sesh.recv_response())



if __name__ == "__main__":
    testSMTPSession()
