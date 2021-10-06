import json
import math
import os
import random
import socket
from sys import base_exec_prefix

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from ECPoint import ECPoint
from Parameters import Parameters
from static.SystemFunctions import SystemFunctions
from static.SystemParameters import CONNECTION_PARAMS, HASH_PARAMS, POINT_PARAMS
from threading import *

class Client(Thread):

    def __init__(self, socket, address, identifier, parameters):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.identifier = identifier
        self.parameters = parameters
        self.start()
    
    
    def retrieve_secrets(self, ID):
        path = '.server'
        filepath = os.path.join(path, 'client_secrets.json')
        with open(filepath) as f:
            client_secrets = json.load(f)
        if not client_secrets.get(ID) is None:
            return client_secrets[ID]['pi_0'], client_secrets[ID]['C']
        else:
            return None, None


    def create_register(self, ID, ip_addr, k_enc, k_mac, reg=True):
        path = '.server'
        filepath = os.path.join(path, 'client_register.json')
        with open(filepath) as f:
            client_register = json.load(f)
        client_register[ID] = {
            'IP': ip_addr,
            'k_enc': k_enc,
            'k_mac': k_mac,
            'registered': reg
        }
        with open(filepath, 'w') as f:
            json.dump(client_register, f, indent=4)

    
    def update_registered_ip(self, ID, ip_addr):
        path = '.server'
        filepath = os.path.join(path, 'client_register.json')
        with open(filepath) as f:
            client_register = json.load(f)
        if not client_register.get(ID) is None:
            if client_register[ID]['registered']:
                client_register[ID]['IP'] = ip_addr
                with open(filepath, 'w') as f:
                    json.dump(client_register, f, indent=4)
                return 'success'
            return 'error: cliente no registrado'
        return 'error: cliente no existe'


    def verify_registered(self, ID):
        path = '.server'
        filepath = os.path.join(path, 'client_register.json')
        with open(filepath) as f:
            client_register = json.load(f)
        if not client_register.get(ID) is None:
            return client_register[ID]['registered']
        return False


    def retrieve_register_ip(self, ID):
        path = '.server'
        filepath = os.path.join(path, 'client_register.json')
        with open(filepath) as f:
            client_register = json.load(f)
        if not client_register.get(ID) is None:
            if client_register[ID]['registered']:
                return 'ip: ' + client_register[ID]['IP']
            return 'error: cliente no registrado'
        return 'error: cliente no existe'


    def update_secrets(self, ID, pi_0, chex):
        try:
            path = '.server'
            filepath = os.path.join(path, 'client_secrets.json')
            with open(filepath) as f:
                client_secrets = json.load(f)
            client_secrets[ID] = {
                'pi_0': pi_0,
                'C': chex
            }
            with open(filepath, 'w') as f:
                json.dump(client_secrets, f, indent=4)
            message = 'success'
        except:
            message = 'error'
        return message


    def retrieve_keys(self, ID):
        path = '.server'
        filepath = os.path.join(path, 'client_register.json')
        with open(filepath) as f:
            client_register = json.load(f)
        if not client_register.get(ID) is None:
            if client_register[ID]['registered']:
                return client_register[ID]['k_enc'], client_register[ID]['k_mac']

    
    def run(self):
        try:
            response = self.receive()
            L = SystemFunctions.decodeArray(response)

            if L[0] == b'preregistrar':
                try:
                    path = '.server'
                    filepath = os.path.join(path, 'client_secrets.json')
                    with open(filepath) as f:
                        client_secrets = json.load(f)

                    key_c = L[1].decode('utf-8')
                    pi_0 = int.from_bytes(L[2], 'big')
                    client_secrets[key_c] = {
                        'pi_0': pi_0,
                        'C': L[3].hex()
                    }
                    with open(filepath, 'w') as f:
                        json.dump(client_secrets, f, indent=4)
                    message = b'success'
                except:
                    message = b'error'

                to_send = [message]
                self.send(SystemFunctions.encodeArray(to_send))
                self.sock.close()
            elif L[0] == b'third_party':
                response = self.receive()
                L = SystemFunctions.decodeArray(response)
                ubytes = L[0]
                id_c = L[1]

                U = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, ubytes)

                # Verify (yr = yu^2) == (xr = xu^3 - 3xu + b)
                yr = U.y ** 2
                xr = U.x ** 3 + self.parameters.a * U.x + self.parameters.b
                if U.is_identity() or not xr == yr:
                    print('Connection Closed')
                    self.sock.close()
                    raise RuntimeError('Error on Verification')

                id_cs = id_c.decode('utf-8')

                # Retreive
                pi_0, C_hex = self.retrieve_secrets(id_cs)
                C = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, bytes.fromhex(C_hex))

                beta = random.randint(1, self.parameters.q - 1)
                
                V1 = self.parameters.G.point_multiplication(beta)
                V2 = self.parameters.B.point_multiplication(pi_0)
                V = V1 + V2
                vbytes = V.to_bytes()
                id_s = bytes(self.identifier, 'utf-8')

                U2 = self.parameters.A.point_multiplication(pi_0)
                W = (U - U2).point_multiplication(beta)
                d = C.point_multiplication(beta)

                L = [vbytes, id_s]
                array = SystemFunctions.encodeArray(L)
                self.send(SystemFunctions.encodeArray([array]))

                # Get k
                wbytes = W.to_bytes()
                dbytes = d.to_bytes()
                pi0bytes = pi_0.to_bytes(math.ceil(self.parameters.n / 8), byteorder='big')

                k = SystemFunctions.Hi([pi0bytes, ubytes, vbytes, wbytes, dbytes], 
                                            fixed_str=HASH_PARAMS['H1'][0], n=HASH_PARAMS['H1'][1])
                
                T2a = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H2'][0], n=HASH_PARAMS['H2'][1])
                T2b = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H3'][0], n=HASH_PARAMS['H3'][1])

                arrayRec = self.receive()
                L = SystemFunctions.decodeArray(arrayRec)
                T1b = L[0]

                to_verif = SystemFunctions.encodeArray([T2a])
                self.send(SystemFunctions.encodeArray([to_verif]))

                if T1b != T2b:
                    print('Connection Closed')
                    self.sock.close()

                keyblob = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H4'][0], n=HASH_PARAMS['H4'][1])
                key, nonce = keyblob[:32], keyblob[32:]
                mask = int('0xffffffffffffffffffffffff', base=16)
                vnonce = int.from_bytes(nonce, 'big')

                data = self.receive() 
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(data[16:], data[:16]) 
                vnonce = (vnonce + 1) & mask
                
                plaintext = plaintext.decode('utf-8')
                tp_info = plaintext.split(',')

                idA = tp_info[1]
                idB = tp_info[3]

                rA = bytes.fromhex(tp_info[0])
                rB = bytes.fromhex(tp_info[2])

                bA = self.verify_registered(idA)
                bB = self.verify_registered(idB)
                if not bA or not bB:
                    print('Error')

                k_encAh, k_macAh = self.retrieve_keys(idA)
                k_encA, k_macA = bytes.fromhex(k_encAh), bytes.fromhex(k_macAh)

                k_encBh, k_macBh = self.retrieve_keys(idB)
                k_encB, k_macB = bytes.fromhex(k_encBh), bytes.fromhex(k_macBh)

                k = get_random_bytes(32)

                cipher = AES.new(k_encB, mode=AES.MODE_CBC)
                ciphertextB = cipher.encrypt(k)
                cB = ciphertextB.hex()

                m = bytes(idA, 'utf-8') + rA + rB + ciphertextB
                hmac_ = HMAC.new(k_macB, digestmod=SHA256)
                hmac_.update(m)
                tB = hmac_.hexdigest()

                to_send = bytes(f'{cB},{tB}', 'utf-8')
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(to_send)
                vnonce = (vnonce + 1) & mask

                array = SystemFunctions.encodeArray([tag + ciphertext])
                self.send(array)

                self.sock.close()
            else:
                ubytes = L[0]
                id_c = L[1]

                U = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, ubytes)

                # Verify (yr = yu^2) == (xr = xu^3 - 3xu + b)
                yr = U.y ** 2
                xr = U.x ** 3 + self.parameters.a * U.x + self.parameters.b
                if U.is_identity() or not xr == yr:
                    print('Connection Closed')
                    self.sock.close()
                    raise RuntimeError('Error on Verification')

                id_cs = id_c.decode('utf-8')

                # Retreive
                pi_0, C_hex = self.retrieve_secrets(id_cs)
                C = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, bytes.fromhex(C_hex))

                beta = random.randint(1, self.parameters.q - 1)
                
                V1 = self.parameters.G.point_multiplication(beta)
                V2 = self.parameters.B.point_multiplication(pi_0)
                V = V1 + V2
                vbytes = V.to_bytes()
                id_s = bytes(self.identifier, 'utf-8')

                U2 = self.parameters.A.point_multiplication(pi_0)
                W = (U - U2).point_multiplication(beta)
                d = C.point_multiplication(beta)

                L = [vbytes, id_s]
                array = SystemFunctions.encodeArray(L)
                self.send(SystemFunctions.encodeArray([array]))

                # Get k
                wbytes = W.to_bytes()
                dbytes = d.to_bytes()
                pi0bytes = pi_0.to_bytes(math.ceil(self.parameters.n / 8), byteorder='big')

                k = SystemFunctions.Hi([pi0bytes, ubytes, vbytes, wbytes, dbytes], 
                                            fixed_str=HASH_PARAMS['H1'][0], n=HASH_PARAMS['H1'][1])
                
                T2a = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H2'][0], n=HASH_PARAMS['H2'][1])
                T2b = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H3'][0], n=HASH_PARAMS['H3'][1])

                arrayRec = self.receive()
                L = SystemFunctions.decodeArray(arrayRec)
                T1b = L[0]

                to_verif = SystemFunctions.encodeArray([T2a])
                self.send(SystemFunctions.encodeArray([to_verif]))

                if T1b != T2b:
                    print('Connection Closed')
                    self.sock.close()

                keyblob = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H4'][0], n=HASH_PARAMS['H4'][1])
                key, nonce = keyblob[:32], keyblob[32:]
                mask = int('0xffffffffffffffffffffffff', base=16)
                vnonce = int.from_bytes(nonce, 'big')
                cont = True
                
                while cont:
                    data = self.receive()
                    try: 
                        nonce = vnonce.to_bytes(12, byteorder='big')
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        plaintext = cipher.decrypt_and_verify(data[16:], data[:16]) 
                        vnonce = (vnonce + 1) & mask
                        
                        plaintext = plaintext.decode('utf-8')
                        operation = plaintext.split(':')[0]
                        if operation == 'registrar':
                            ip_addr = plaintext.split(':')[1].strip()
                            ip_addr = ip_addr.replace(',', ':')
                            k_enc, k_mac = get_random_bytes(32), get_random_bytes(32)
                            self.create_register(ID=id_cs, ip_addr=ip_addr, k_enc=k_enc.hex(), k_mac=k_mac.hex())
                            to_send = k_enc + k_mac
                            nonce = vnonce.to_bytes(12, byteorder='big')
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            ciphertext, tag = cipher.encrypt_and_digest(to_send)
                            vnonce = (vnonce + 1) & mask

                            array = SystemFunctions.encodeArray([tag + ciphertext])
                            self.send(array)
                        elif operation == 'obtenerIP':
                            id_b = plaintext.split(':')[1].strip()
                            if self.verify_registered(id_cs):
                                message = self.retrieve_register_ip(id_b)
                            else:
                                message = 'error: usted no esta registrado'
                            
                            data = bytes(message, 'utf-8')
                            nonce = vnonce.to_bytes(12, byteorder='big')
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            ciphertext, tag = cipher.encrypt_and_digest(data)
                            vnonce = (vnonce + 1) & mask

                            array = SystemFunctions.encodeArray([tag + ciphertext])
                            self.send(array)
                        elif operation == 'actualizar':
                            ip_addr = plaintext.split(':')[1].strip()
                            ip_addr = ip_addr.replace(',', ':')
                            message = self.update_registered_ip(ID=id_cs, ip_addr=ip_addr)
                            data = bytes(message, 'utf-8')
                            nonce = vnonce.to_bytes(12, byteorder='big')
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            ciphertext, tag = cipher.encrypt_and_digest(data)
                            vnonce = (vnonce + 1) & mask

                            array = SystemFunctions.encodeArray([tag + ciphertext])
                            self.send(array)
                        elif operation == 'actualizarPass':
                            secrets_ = plaintext.split(':')[1].split(',')
                            pi_0n, chexn = int(secrets_[0]), secrets_[1]
                            message = self.update_secrets(ID=id_cs, pi_0=pi_0n, chex=chexn)
                            data = bytes(message, 'utf-8')
                            nonce = vnonce.to_bytes(12, byteorder='big')
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            ciphertext, tag = cipher.encrypt_and_digest(data)
                            vnonce = (vnonce + 1) & mask

                            array = SystemFunctions.encodeArray([tag + ciphertext])
                            self.send(array)
                        elif operation == 'exit':
                            to_send = bytes('Connection closed', 'utf-8')
                            nonce = vnonce.to_bytes(12, byteorder='big')
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            ciphertext, tag = cipher.encrypt_and_digest(to_send)
                            vnonce = (vnonce + 1) & mask

                            array = SystemFunctions.encodeArray([tag + ciphertext])
                            self.send(array)
                            cont = False
                        else:
                            to_send = bytes('Unknown operation', 'utf-8')
                            nonce = vnonce.to_bytes(12, byteorder='big')
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            ciphertext, tag = cipher.encrypt_and_digest(to_send)
                            vnonce = (vnonce + 1) & mask

                            array = SystemFunctions.encodeArray([tag + ciphertext])
                            self.send(array)
                    except:
                        raise RuntimeError('Encryption Error')
                
                self.sock.close()
                
        except Exception as e:
            print('Error:', e)
            self.sock.close()
            
            
    def send(self, msg):
        totalsent = 0
        msglen = len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent


    def receive(self):
        bytes_recd = 0
        chunk = self.sock.recv(4)
        if chunk == b'':
            self.sock.close()

        bytes_recd = 0
        msglen = int.from_bytes(chunk, byteorder='big')
        chunks = []
        while bytes_recd < msglen:
            chunk = self.sock.recv(min(msglen - bytes_recd, 2048))
            if chunk == b'':
                self.sock.close()
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        
        return b''.join(chunks)


if __name__ == '__main__':
    # Get Connection Parameters
    identifier = CONNECTION_PARAMS['SERVER_ID']
    host, port = '', CONNECTION_PARAMS['SERVER_PORT']
    
    # Create Server Folder if not Exists
    path = '.server'
    if not os.path.exists(path):
        os.makedirs(path)

    # Create Client Secrets File if not Exists
    filepath = os.path.join(path, 'client_secrets.json')
    if not os.path.exists(filepath):
        with open(filepath, 'w') as f:
            json.dump({}, f)

    # Create Client Register File if not Exists
    filepath = os.path.join(path, 'client_register.json')
    if not os.path.exists(filepath):
        with open(filepath, 'w') as f:
            json.dump({}, f)
    
    # Create Server Socket
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((host, port))
    serversocket.listen(40)

    print('Server Started and Listening')

    # Create Parameters Set
    xa = POINT_PARAMS['xA']
    ya = POINT_PARAMS['yA']
    xb = POINT_PARAMS['xB']
    yb = POINT_PARAMS['yB']

    param = Parameters(xa, ya, xb, yb)
    
    # Wait for Clients
    while True:
        clientsocket, address = serversocket.accept()
        Client(socket=clientsocket, address=address, identifier=identifier, parameters=param)