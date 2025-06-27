# ftp_server.py

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Set up a simple user account
authorizer = DummyAuthorizer()
authorizer.add_user("user", "12345", ".", perm="elradfmw")  # Username: user, Password: 12345

# Configure FTP handler with the authorizer
handler = FTPHandler
handler.authorizer = authorizer

# Set up and start the FTP server
server = FTPServer(("0.0.0.0", 21), handler)
print("FTP Server running on port 21...")
# Start the server  
print("Commands:")
print("1. Connect to the server using an FTP client.")
print("2. Use the username 'user' and password '12345'.")   
print("ls - List files in the current directory.")
print("get <filename> - Download a file.")
print("put <filename> - Upload a file.") 
print("delete <filename> - Delete a file.")
print("quit - Disconnect from the server.")
print("bye - To stop the server.")
print("To stop the server, press Ctrl+C.")

server.serve_forever()
