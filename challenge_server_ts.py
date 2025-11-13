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

    
from ast import literal_eval

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G1,GT,pair

import tenseal as ts

def writeInEncFile(enc_vec, filename):
    ser_vec = base64.b64encode(enc_vec)

    with open(filename, 'wb') as f:
        f.write(ser_vec)

def readfromEncFile(filename):
    with open(filename, 'rb') as f:
        ser_vec = f.read()
    
    return base64.b64decode(ser_vec)

group = PairingGroup('SS512')
order = group.order()

#os.system('python3 extprotocol32.py')

# Define the function f(c)
def f(c):
    n = 32
    m = 32
    p = 1381819329670992382493016885514578963637936154479   ##p is a 160-bit prime public
   # with open('prime.pkl', 'rb') as file:
   #     p = pickle.load(file)
    #print(p)


    with open('auth-2.json', 'r') as file:
        data = json.load(file)

    g = group.deserialize(base64.b64decode(data["generator"]))
    v = group.deserialize(base64.b64decode(data["ppm"]))

    SS = data["points"]
    SSD = []
    for i in range(n):
        SSD.append( group.deserialize(base64.b64decode(SS[i])) )

    #print("g", g)
    #print("v", v)

    #SS = [
    #[point["x"], point["y"]]
    #for point in loaded_serialized_points]

    #print("Restored:", P_restored)

    contexts = []
    for index in range(8):
        data = readfromEncFile("out/public_context"+str(index))
        context = ts.context_from(data)
        contexts.append(context)

    EMT = []
    ciphertext_template="out/enc_vec_{}_{}"
    for j in range(m):
        enc_vecs = []
        for i, context in enumerate(contexts):
            fname = ciphertext_template.format(i, j)
            if not os.path.exists(fname):
                raise FileNotFoundError(f"Missing ciphertext file: {fname}")
            
            # deserialize bfv tensor into a TenSEAL object
            ct = ts.bfv_tensor_from(context, readfromEncFile(fname))
            enc_vecs.append(ct)
        EMT.append(enc_vecs)
    
    '''
    with open('ctext.pkl', 'rb') as file:
        EMTP = pickle.load(file)



    # for the sake of simplicity server is allowed to acces private key, public key file. But only downloads public key
    with open("keys.pkl", "rb") as f: 
        keys = pickle.load(f)
    
    pub_key = keys["public_key"]
    priv_key = keys["private_key"]
    #print("public key", pub_key.n)

    print("Server has loaded everything")

    #Reconstruct ciphertext
    EMT = []
    for j in range(m):
        TM = []
        for i in range(n):
            reconstructed_ciphertext = paillier.EncryptedNumber(pub_key, EMTP[j][i][0], EMTP[j][i][1])
            TM.append(reconstructed_ciphertext)
        EMT.append(TM)

    #print("decryption", priv_key.decrypt(EMT[0][0]))

    #print("server computation on reconstructed ciphertext")
    '''

    bh = [] #bh contains encoded (reformatted) challenges

    for i in range(n):
        bh.append(c[i]%p)
        #print(c[i]%p)

    '''
    deltat = [] # encrypted response based on EMT
    for j in range(m):
        ct = EMT[j][0]*bh[0]
        for i in range(1,n):
            ct = ct + EMT[j][i]*bh[i]
        deltat.append(ct)
    '''

    bh_residues = []                   # holds residues for this row across all moduli
    for mod in moduli:                  # for each modulus
        mod_res = [x % mod for x in bh]   # residue vector for this modulus
        bh_residues.append(mod_res)
    
    bh_enc_vecs = []
    for i, context in enumerate(contexts):
        bh_enc_vec = ts.bfv_tensor(context, ts.plain_tensor(bh_residues[i]), True)
        bh_enc_vecs.append(bh_enc_vec)
        
    for j in range(m):
        delt = []
        for i, context in enumerate(contexts):
            ct = EMT[j][i] * bh_enc_vecs[i]       # elementwise multiplication (encrypted × plaintext)
            sum_ct = ct.sum()      # homomorphic sum across all slots
            writeInEncFile(sum_ct.serialize(), "out/sum_ct"+"_"+str(i)+"_"+str(j))
            delt.append(sum_ct)
        deltat.append(delt)


   # print("SSD")
    #print(SSD[0])
    SIG = SSD[0]**bh[0] # combined signature
    for i in range(1,n):
        sigv =  (SSD[i] ** bh[i])
        SIG = SIG*sigv

    #print("SIG", SIG)
    SIG_serialized = base64.b64encode(group.serialize(SIG)).decode() # serialize g and convert to base64
    #result =[deltat, SIG]


#    with open('response.json', 'w') as file:
#        json.dump({
#            "ciphertext": deltat,
#            "authenticator": SIG_serialized
#            }, file)



    cipher_data = pickle.dumps([{
        "ciphertext": ct.ciphertext(),   # integer
        "exponent": ct.exponent          # integer
    } for ct in deltat])


    #pickle.dumps(cipher_data)
    client_socket.sendall(len(cipher_data).to_bytes(4, 'big'))
    client_socket.sendall(cipher_data)




    '''payload_cipher = pickle.dumps({
            "ciphertext": deltat,
    })'''

    payload_SIG = json.dumps({
            "authenticator": SIG_serialized
    })
            


    client_socket.sendall(len(payload_SIG.encode('utf-8')).to_bytes(4, 'big'))
    client_socket.sendall(payload_SIG.encode('utf-8'))


    #client_socket.sendall(payload_SIG.encode('utf-8'))
    #client_socket.sendall(pickle.dumps(payload_cipher)) 

    #client_socket.sendall(payload_all) 

    return(0)
    #return("Response is written in response.json")

# Set up the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

host = '127.0.0.1'  # Localhost
port = 12345  # Choose an open port

server_socket.bind((host, port))
server_socket.listen(1)
print(f"Server is listening on {host}:{port}")

# Accept a connection
client_socket, client_address = server_socket.accept()
print(f"Connection established with {client_address}")

# Receive the challenge c from the client
data = client_socket.recv(4096)
c = pickle.loads(data)
print(f"Received challenge: c = {c}")


# Compute f(c)
result = f(c)


#print(f"Computed result: f(c) = {result}")

#with open('auth-2.json', 'r') as file:
#    data = json.load(file)

# Send the result back to the client
#client_socket.send(str(result).encode('utf-8'))




# Close the connections
client_socket.close()
server_socket.close()

