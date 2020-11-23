import socket
import base64
from tls_session import TlsSession

def testSMTPSession():
    email = b'Subject: This email was sent from my SMTP implementation\r\nFrom: "Little, Ryan Jay" <littler@oregonstate.edu>\r\nTo: <mike.rosulek@oregonstate.edu>\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\n\xf0\x9f\x98\x8e\r\n-Ryan\r\n.\r\n'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = socket.gethostbyname("smtp.gmail.com")
    sock.connect((ip, 587))
    print(f"Connected to {ip}")
    res = sock.recv(128)
    print(res)
    ehlo = b'EHLO mail.oregonstate.edu\r\n'
    sock.send(ehlo)
    res = sock.recv(512)
    print(res.split(b'\r\n'))
    sock.send(b'STARTTLS\r\n')
    print(sock.recv(512))
    tls_sesh = TlsSession("smtp.gmail.com", port=587, logging=True)
    tls_sesh.socket = sock
    tls_sesh._handshake()
    tls_sesh.send(ehlo)
    print(tls_sesh.recv_response().split(b'\r\n'))
    tls_sesh.send(b'AUTH LOGIN\r\n')
    print(tls_sesh.recv_response())
    username = base64.b64encode(b'littler@oregonstate.edu') + b'\r\n'
    password = base64.b64encode(b'my password here') + b'\r\n'
    tls_sesh.send(username)
    print(tls_sesh.recv_response())
    tls_sesh.send(password)
    print(tls_sesh.recv_response())
    tls_sesh.send(b'MAIL FROM:<littler@oregonstate.edu>\r\n')
    print(tls_sesh.recv_response())
    tls_sesh.send(b'RCPT TO:<mike.rosulek@oregonstate.edu>\r\n')
    print(tls_sesh.recv_response())
    tls_sesh.send(b'DATA\r\n')
    print(tls_sesh.recv_response())
    tls_sesh.send(email)
    print(tls_sesh.recv_response())
    tls_sesh.send(b'QUIT\r\n')
    print(tls_sesh.recv_response())




if __name__ == "__main__":
    testSMTPSession()
