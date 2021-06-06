from bob import BobTlsSession
import sys
import base64

password_share = b'\x00'*24

f = open("email", "rb")
email = f.read()

def testSMTPSession():
    print(email)
    port = int(sys.argv[1])
    username = base64.b64encode(b'mpcemailtest@gmail.com') + b'\r\n'
    password = bytes(32) + b'\r\n'
    session = BobTlsSession(port=port, logging=True)
    session.openConnection()
    session.getKey()
    session.sendFinishedMPC()

    ehlo = b'EHLO mail.google.com\r\n'
    session.send(ehlo)
    session.send(b'AUTH LOGIN\r\n')
    session.send(username)
    session.sendPassword(password)
    session.send(b'MAIL FROM:<mpcemailtest@gmail.com>\r\n')
    session.send(b'RCPT TO:<littler@oregonstate.edu>\r\n')
    session.send(b'DATA\r\n')
    session.send(email)
    session.send(b'QUIT\r\n')

if __name__ == "__main__":
    testSMTPSession()
