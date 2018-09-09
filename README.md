# MySSL
An SSL implementation 

To compile:  
&nbsp;go to server's src folder, do the following in command line:  
&nbsp;javac *.java  
&nbsp;go to client's src folder, do the following in command line:  
&nbsp;javac *.java  

To run:  
&nbsp;go to server's src folder, do the following in command line:  
&nbsp;java ServerDriver  
&nbsp;go to client's src folder, do the following in command line:  
&nbsp;java ClientDriver  
    
## Handshake Phase   
• The client and the server authenticate each other using certificates. The certificates (self-assigned) are created and included in the mySSL messages.
  
• The client also informs the server what data encryption and integrity protection scheme to use (there is no negotiation). eg. RSA  
  
• The client and server also send encrypted nonces to each other. These nonces are then xored to create a master secret.  
  
• A computed hash of all messages exchanged at both the client and server and these hashes are exchanged. The keyed SHA-1 is used for computing the hash. The client appends the string CLIENT for computing its keyed hash and the server appends the string SERVER for computing its keyed hash. The keyed hashes at the client and the server are verified.  
  
• Four keys (two each for encryption, authentication, in each direction of the communication between the client and the server) are generated using this master secret.  
  
    
## Data Phase  
• Now we can transfer a file, from the server to client.  
  
• Decrypting the file at the client and doing a diff of the original and the decrypted file on the MAC Terminal utility could ensure that the secure file transfer was successful.  
