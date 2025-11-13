import socket

import os

import sys
import phe
import time
import random
import math

import pickle
import json
import base64

from phe import paillier
from phe import util

import sympy
from math import prod, gcd
from typing import List, Tuple
    
from ast import literal_eval

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G1,GT,pair
            

n= 32
m = 32
p = 1381819329670992382493016885514578963637936154479
tao = 2 ** 90


def decode(x):
    if x >= p/2:
        return (x - p)/tao
    else:
        return x/tao


import tenseal as ts

# ---------- math helpers ----------
def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

def crt_reconstruct(residues: List[int], moduli: List[int]) -> Tuple[int, int]:
    """Reconstruct x mod M, where M = product(moduli). Returns (x, M)."""
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for (r_i, m_i) in zip(residues, moduli):
        M_i = M // m_i
        inv = inv_mod(M_i, m_i)
        x = (x + (r_i * M_i % M) * inv) % M
    return x, M

def readfromEncFile(filename):
    with open(filename, 'rb') as f:
        ser_vec = f.read()
    
    return base64.b64decode(ser_vec)

# helper to receive exactly n bytes
def recv_all(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("socket closed")
        data.extend(packet)
    return bytes(data)

'''
with open("keys.pkl", "rb") as f:
    keys = pickle.load(f)

pub_key = keys["public_key"]
priv_key = keys["private_key"]
'''

moduli = [549756026881, 1099511922689, 2199023288321, 4398047051777, 4398055555073, 4398071955457, 4398088339457, 4398104608769]
contexts = []
for index in range(8):
    data = readfromEncFile("out/public_context"+str(index))
    context = ts.context_from(data)
    contexts.append(context)

#print("n =", pub_key.n)

# Compute the challenge c
PC = []
for i in range(n):
    b = random.randrange(0,2)
    PC.append(1-2*b)

#print(f"Computed challenge: PC = {PC}")

data = pickle.dumps(PC)


group = PairingGroup('SS512')



# Set up the client for the PUF
client_socket_puf  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host_puf = '127.0.0.1'  # Server's IP
port_puf = 12346  # Same port as the server

client_socket_puf.connect((host_puf, port_puf))
print(f"CoNnected to the PUF at {host_puf}:{port_puf}")

# Send the challenge to the PUF
client_socket_puf.sendall(data)

# Receive the PUF data c from the PUF
puf_resp = client_socket_puf.recv(4096)
AC_f = pickle.loads(puf_resp)

print("Recieved PUF response")
print(AC_f)
#--------------------------------------

# Set up the client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'  # Server's IP
port = 12345  # Same port as the server

client_socket.connect((host, port))
print(f"Connected to server at {host}:{port}")



# Send the challenge to the server
client_socket.sendall(data)


# Receive the resposne from Server
'''
payload = b''
while True:
    chunk = client_socket.recv(4096)
    if not chunk:
        break
    payload += chunk

response_SIG = json.loads(payload.decode('utf-8'))

print(response_SIG)




payload_cipher = b''
while True:
    chunk = client_socket.recv(4096)
    if not chunk:
        break
    payload_cipher += chunk

enc_puf_resp = pickle.loads(payload_cipher)["ciphertext"]

#enc_puf_resp = response["ciphertext"]
print(enc_puf_resp)
#print(len(enc_puf_resp))


SIG = group.deserialize(base64.b64decode(response_SIG["authenticator"]))

print(SIG)

'''


def recv_with_length(sock):
    length_bytes = sock.recv(4)
    total_length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < total_length:
        data += sock.recv(total_length - len(data))
    return data


'''
pickle_payload = recv_with_length(client_socket)


recv_ct = pickle.loads(pickle_payload)


print("received ciphertext matches with sent ciphertext")


#Remdconstruct ciphertext

recon_ct = []
for item in recv_ct:
    enc_number = paillier.EncryptedNumber(pub_key, item["ciphertext"], item["exponent"])
    recon_ct.append(enc_number)



#decryption of Ciphertext receive from Server
DELTAT = [priv_key.decrypt(ct) for ct in recon_ct]


DELTAT = []
ciphertext_template="out/sum_ct{}_{}"
for j in range(m):
    enc_vecs = []
    for i, context in enumerate(contexts):
        fname = ciphertext_template.format(i, j)
        if not os.path.exists(fname):
            raise FileNotFoundError(f"Missing ciphertext file: {fname}")
        
        # deserialize bfv tensor into a TenSEAL object
        ct = ts.bfv_tensor_from(context, readfromEncFile(fname))
        enc_vecs.append(ct)
    DELTAT.append(enc_vecs)
'''

length_bytes = recv_all(client_socket, 8)
length = int.from_bytes(length_bytes, "big")
blob = recv_all(client_socket, length)
payload = pickle.loads(blob)

rows = payload["rows"]
cols = payload["cols"]
cipher_bytes = payload["ciphers"]

# reconstruct 2D list of BFV tensors
deltat = []
idx = 0
for r in range(rows):
    row_cts = []
    for c in range(cols):
        b = cipher_bytes[idx]; idx += 1
        # Use the corresponding context for column c (receiver must have contexts list)
        ctx = contexts[c]                 # contexts[c] must be loaded already
        ct = ts.bfv_tensor_from(ctx, b)  # reconstruct BFVTensor
        row_cts.append(ct)
    deltat.append(row_cts)

DELTAT = []
for j in range(m):  # for each row
    row_residues = []
    for i, mod in enumerate(moduli):  # for each modulus/context
        # decrypt ciphertext under its context
        decrypted_val = deltat[j][i].decrypt().tolist()
        value = int(decrypted_val) % mod
        row_residues.append(value)

    # Combine residues via CRT if you used multiple moduli
    combined, M = crt_reconstruct(row_residues, moduli)  # <-- you'll need your crt_combine() from before
    reconstructed = int(combined)

    DELTAT.append(reconstructed)

json_payload = recv_with_length(client_socket)
SIG_load = json.loads(json_payload.decode('utf-8'))

SIG =  group.deserialize(base64.b64decode(SIG_load["authenticator"]))

#------------------------------------------

# Verification --------------------------




with open('auth-2.json', 'r') as file:
        auth_file = json.load(file)

g = group.deserialize(base64.b64decode(auth_file["generator"]))
v = group.deserialize(base64.b64decode(auth_file["ppm"]))



with open('U.json', 'r') as file:
        u_file = json.load(file)

u_points = u_file["rand_points"]

u = []
for pt in u_points: # There are total m points
    u.append( group.deserialize(base64.b64decode(pt)) )


bh = [] #bh contains encoded (reformatted) challenges

for i in range(n):
    bh.append(PC[i]%p)
    #print(c[i]%p)

'''DELTAT = [] # decryption of server's respponse based on T
for i in range(m):
    DELTAT.append(priv_key.decrypt(server_enc[i]))
'''




#print(DELTA)
# print(decode(DELTAT[0]), decode(DELTAT[1]))
# exit(0)

GH = []
for i in range(n):
    GH.append(group.hash(str("PID")+str(i), G1) )


#vr = GH[0] ** PC[0]
vr = GH[0] ** bh[0]
for i in range(1, n):
    #vr = vr * ( GH[i] ** PC[i])
    vr = vr * ( GH[i] ** bh[i])

print("u[0]**DELTAT[0]", u[0],DELTAT[0])

#agm_a = u[0]**DELTA[0]
agm_a = u[0]**DELTAT[0]
for i in range(1, m):
    te = u[i]**DELTAT[i]
    agm_a = agm_a*te
vrf = vr*agm_a

rhs = pair(vrf, v) # right hand side value of the verification 
lhs = pair(SIG, g) # left hand side value of the verification 


# if (vrf**alpha != SIG):
#     print("vrf, SIG mismatch")
if (lhs != rhs ):
    print("Linear authenticator mismatch")
    #print(bh)
    exit(0)


R_f = []
for i in range(m):
    #if DELTA[i] >= 0:
    z = decode(DELTAT[i] % p)
    if z >= 0:
        #print(1)
        R_f.append(1)
    else:
        #print(0)
        R_f.append(0)
#print(R_f)

#print("puf", DELTA)
if (AC_f != R_f):
    print("server response and PUF response mismatch")
    exit(0)
print("verification successful")



# Receive the result f(c) from the server
#result = client_socket.recv(1024).decode('utf-8')

#resp = client_socket.recv(1073741824).decode('utf-8')

#print(f"Received result: f(PC) = {result}")


#payload = json.loads(resp)
#reps1 = group.deserialize(base64.b64decode(resp["authenticator"]))

#print(response)
#resp1 = json.loads(resp.decode('utf-8'))




# Close the connection
client_socket.close()

