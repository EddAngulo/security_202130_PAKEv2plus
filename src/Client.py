import json
import math
import os
import random
import socket

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from ECPoint import ECPoint
from getpass import getpass
from Parameters import Parameters
from static.SystemFunctions import SystemFunctions
from static.SystemParameters import CONNECTION_PARAMS, HASH_PARAMS, POINT_PARAMS
from threading import *

class Client2Server:
  
    def __init__(self, sock, identifier, password, host, port, parameters, listening_host, listening_port):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

        self.host = host
        self.port = port
        self.password = password
        self.identifier = identifier
        self.parameters = parameters
        self.listening_host = listening_host
        self.listening_port = listening_port
    

    def generate_secrets(self):
        input_ = self.password + self.identifier + CONNECTION_PARAMS['SERVER_ID']
        salt = get_random_bytes(16)
        nb = math.ceil(self.parameters.n / 8)
        h = PBKDF2(input_, salt, 2 * nb, count=100000, hmac_hash_module=SHA512)

        pi_0p = int.from_bytes(h[:nb], 'big') 
        pi_1p = int.from_bytes(h[nb:], 'big')

        pi_0 = pi_0p % self.parameters.q
        pi_1 = pi_1p % self.parameters.q

        return pi_0, pi_1


    def preregister(self):
        # Get Actual Secrets
        path = '.client'
        filepath = os.path.join(path, f'{self.identifier}.json')
        with open(filepath) as f:
            secrets_ = json.load(f)

        pi_0, pi_1 = self.generate_secrets()
        C = self.parameters.G.point_multiplication(pi_1)

        pi0bytes = pi_0.to_bytes(math.ceil(self.parameters.n / 8), byteorder='big')
        cbytes = C.to_bytes()
        id_c = bytes(self.identifier, 'utf-8')

        self.connect(self.host, self.port)

        operation = b'preregistrar'
        to_send = [operation, id_c, pi0bytes, cbytes]
        to_send = SystemFunctions.encodeArray(to_send)
        self.send(SystemFunctions.encodeArray([to_send]))
        
        response = self.receive()

        self.sock.close()

        if response == b'success':
            secrets_['pi_0'] = pi_0
            secrets_['pi_1'] = pi_1
            with open(filepath, 'w') as f:
                json.dump(secrets_, f, indent=4)
            return True
        return False


    def get_secrets(self):
        path = '.client'
        filepath = os.path.join(path, f'{self.identifier}.json')
        with open(filepath) as f:
            secrets_ = json.load(f)
        return secrets_['pi_0'], secrets_['pi_1']


    def get_keys(self):
        path = '.client'
        filepath = os.path.join(path, f'{self.identifier}.json')
        with open(filepath) as f:
            secrets_ = json.load(f)
        return secrets_['k_enc'], secrets_['k_mac']


    def save_keys(self, k_enc=None, k_mac=None):
        if not k_enc is None and not k_mac is None:
            path = '.client'
            filepath = os.path.join(path, f'{self.identifier}.json')
            with open(filepath) as f:
                secrets_ = json.load(f)
            secrets_['k_enc'] = k_enc
            secrets_['k_mac'] = k_mac
            with open(filepath, 'w') as f:
                json.dump(secrets_, f, indent=4)
            return True
        return False
        
    
    def run(self):
        self.connect(self.host, self.port)
        
        pi_0, pi_1 = self.get_secrets()

        alpha = random.randint(1, self.parameters.q - 1)
        U1 = self.parameters.G.point_multiplication(alpha)
        U2 = self.parameters.A.point_multiplication(pi_0)
        U = U1 + U2
        
        ubytes = U.to_bytes()
        id_c = bytes(self.identifier, 'utf-8')
        
        L = [ubytes, id_c]
        array = SystemFunctions.encodeArray(L) 
        self.send(SystemFunctions.encodeArray([array]))

        arrayRec = self.receive()
        L = SystemFunctions.decodeArray(arrayRec)
        vbytes = L[0]
        id_s = L[1]

        V = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, vbytes)

        # Verify (yr = yu^2) == (xr = xu^3 - 3xu + b)
        yr = V.y ** 2
        xr = V.x ** 3 + self.parameters.a * V.x + self.parameters.b
        if V.is_identity() or not xr == yr:
            print('Connection Closed')
            self.sock.close()
            raise RuntimeError('Error on Verification')

        V2 = self.parameters.B.point_multiplication(pi_0)
        W = (V - V2).point_multiplication(alpha)
        d = (V - V2).point_multiplication(pi_1)

        # Get k
        wbytes = W.to_bytes()
        dbytes = d.to_bytes()
        pi0bytes = pi_0.to_bytes(math.ceil(self.parameters.n / 8), byteorder='big')

        k = SystemFunctions.Hi([pi0bytes, ubytes, vbytes, wbytes, dbytes], 
                                        fixed_str=HASH_PARAMS['H1'][0], n=HASH_PARAMS['H1'][1])

        T1a = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H2'][0], n=HASH_PARAMS['H2'][1])
        T1b = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H3'][0], n=HASH_PARAMS['H3'][1])

        to_verif = SystemFunctions.encodeArray([T1b])
        self.send(SystemFunctions.encodeArray([to_verif]))

        arrayRec = self.receive()
        L = SystemFunctions.decodeArray(arrayRec)
        T2a = L[0]

        if T1a != T2a:
            print('Connection Closed')
            self.sock.close()
            raise RuntimeError('Error on Verification')
        
        keyblob = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H4'][0], n=HASH_PARAMS['H4'][1])
        key, nonce = keyblob[:32], keyblob[32:]
        mask = int('0xffffffffffffffffffffffff', base=16)
        vnonce = int.from_bytes(nonce, 'big')
        cont = True

        while cont:
            print("Escriba un mensaje para enviar (Si escribe 'exit' finaliza la conexión)")
            message = input()
            
            operation = message.split(':')[0]
            if len(message.split(':')) == 1:
                if operation == 'registrar' or operation == 'actualizar':
                    message += f':{self.listening_host},{self.listening_port}'
                elif operation == 'actualizarPass':
                    self.password = getpass('New password: ')

                    pi_0n, pi_1n = self.generate_secrets()
                    Cn = self.parameters.G.point_multiplication(pi_1n)
                    chex = Cn.to_bytes().hex()

                    message += f':{pi_0n},{chex}'

            data = bytes(message, 'utf-8')
            nonce = vnonce.to_bytes(12, byteorder='big')
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            vnonce = (vnonce + 1) & mask

            array = SystemFunctions.encodeArray([tag + ciphertext])
            self.send(array)
            
            response = self.receive()

            if operation == 'registrar':
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(response[16:], response[:16]) 
                vnonce = (vnonce + 1) & mask
                
                success_ = self.save_keys(k_enc=plaintext[:32].hex(), k_mac=plaintext[32:].hex())
                if success_:
                    print('success')
                else:
                    print('error')
            elif operation == 'obtenerIP':
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(response[16:], response[:16]) 
                vnonce = (vnonce + 1) & mask
                
                print(plaintext.decode('utf-8'))
            elif operation == 'actualizar':
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(response[16:], response[:16]) 
                vnonce = (vnonce + 1) & mask
                
                print(plaintext.decode('utf-8'))
            elif operation == 'actualizarPass':
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(response[16:], response[:16]) 
                vnonce = (vnonce + 1) & mask
                
                plaintext = plaintext.decode('utf-8')
                if plaintext == 'success':
                    path = '.client'
                    filepath = os.path.join(path, f'{self.identifier}.json')
                    with open(filepath) as f:
                        secrets_n = json.load(f)
                    secrets_n['pi_0'] = pi_0n
                    secrets_n['pi_1'] = pi_1n
                    with open(filepath, 'w') as f:
                        json.dump(secrets_n, f, indent=4)
                print(plaintext)
            elif operation == 'exit':
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(response[16:], response[:16]) 
                vnonce = (vnonce + 1) & mask
                
                print(plaintext.decode('utf-8'))
                cont = False
            else:
                nonce = vnonce.to_bytes(12, byteorder='big')
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(response[16:], response[:16]) 
                vnonce = (vnonce + 1) & mask
                
                print(plaintext.decode('utf-8'))

        self.sock.close()


    def third_party(self, id_A, rA, rB):
        self.connect(self.host, self.port)
        id_B = bytes(self.identifier, 'utf-8')

        operation = b'third_party'
        to_send = [operation, id_B]
        to_send = SystemFunctions.encodeArray(to_send)
        self.send(SystemFunctions.encodeArray([to_send]))

        pi_0, pi_1 = self.get_secrets()

        alpha = random.randint(1, self.parameters.q - 1)
        U1 = self.parameters.G.point_multiplication(alpha)
        U2 = self.parameters.A.point_multiplication(pi_0)
        U = U1 + U2
        
        ubytes = U.to_bytes()
        id_c = bytes(self.identifier, 'utf-8')
        
        L = [ubytes, id_c]
        array = SystemFunctions.encodeArray(L) 
        self.send(SystemFunctions.encodeArray([array]))

        arrayRec = self.receive()
        L = SystemFunctions.decodeArray(arrayRec)
        vbytes = L[0]
        id_s = L[1]

        V = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, vbytes)

        # Verify (yr = yu^2) == (xr = xu^3 - 3xu + b)
        yr = V.y ** 2
        xr = V.x ** 3 + self.parameters.a * V.x + self.parameters.b
        if V.is_identity() or not xr == yr:
            print('Connection Closed')
            self.sock.close()
            raise RuntimeError('Error on Verification')

        V2 = self.parameters.B.point_multiplication(pi_0)
        W = (V - V2).point_multiplication(alpha)
        d = (V - V2).point_multiplication(pi_1)

        # Get k
        wbytes = W.to_bytes()
        dbytes = d.to_bytes()
        pi0bytes = pi_0.to_bytes(math.ceil(self.parameters.n / 8), byteorder='big')

        k = SystemFunctions.Hi([pi0bytes, ubytes, vbytes, wbytes, dbytes], 
                                        fixed_str=HASH_PARAMS['H1'][0], n=HASH_PARAMS['H1'][1])

        T1a = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H2'][0], n=HASH_PARAMS['H2'][1])
        T1b = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H3'][0], n=HASH_PARAMS['H3'][1])

        to_verif = SystemFunctions.encodeArray([T1b])
        self.send(SystemFunctions.encodeArray([to_verif]))

        arrayRec = self.receive()
        L = SystemFunctions.decodeArray(arrayRec)
        T2a = L[0]

        if T1a != T2a:
            print('Connection Closed')
            self.sock.close()
            raise RuntimeError('Error on Verification')
        
        keyblob = SystemFunctions.Hi([k], fixed_str=HASH_PARAMS['H4'][0], n=HASH_PARAMS['H4'][1])
        key, nonce = keyblob[:32], keyblob[32:]
        mask = int('0xffffffffffffffffffffffff', base=16)
        vnonce = int.from_bytes(nonce, 'big')

        id_As = id_A.decode('utf-8')
        message = f'{rA.hex()},{id_As},{rB.hex()},{self.identifier}'

        data = bytes(message, 'utf-8')
        nonce = vnonce.to_bytes(12, byteorder='big')
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        vnonce = (vnonce + 1) & mask

        array = SystemFunctions.encodeArray([tag + ciphertext])
        self.send(array)
        
        response = self.receive()
        nonce = vnonce.to_bytes(12, byteorder='big')
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(response[16:], response[:16]) 
        vnonce = (vnonce + 1) & mask
        plaintext = plaintext.decode('utf-8')
        serv_data = plaintext.split(',')
        cB, tB = bytes.fromhex(serv_data[0]), serv_data[1]
        
        k_ench, k_mach = self.get_keys()
        k_enc, k_mac = bytes.fromhex(k_ench), bytes.fromhex(k_mach)

        m = bytes(id_As, 'utf-8') + rA + rB + cB
        hmac_ = HMAC.new(k_mac, digestmod=SHA256)
        hmac_.update(m)
        if hmac_.hexdigest() != tB:
            print('Error')

        cipher_cbc = AES.new(k_enc, mode=AES.MODE_CBC)
        kB = cipher_cbc.encrypt(cB)
        if len(kB) != 32:
            print('Error')

        sesion_keys = SystemFunctions.Hi([bytes(id_As, 'utf-8'), id_B, rA, rB, kB], 
                                            fixed_str=HASH_PARAMS['H5'][0], n=HASH_PARAMS['H5'][1])

        print('Sesion keys:')
        print('kA,B :', sesion_keys[:32].hex())
        print('kB,A :', sesion_keys[32:64].hex())
        print('nonce:', sesion_keys[64:].hex())

        self.sock.close()



    def connect(self, host, port):
        self.sock.connect((host, port))
        #c=self.receive()


    def send(self, msg):
        totalsent = 0
        msglen = len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                self.sock.close()
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


class Client2Client:

    def __init__(self, sock, identifier, password, host, port, parameters):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

        self.host = host
        self.port = port
        self.password = password
        self.identifier = identifier
        self.parameters = parameters


    def run(self):
        self.connect(self.host, self.port)
        id_A = bytes(self.identifier, 'utf-8')
        rA = get_random_bytes(16)

        to_send = [rA, id_A]
        to_send = SystemFunctions.encodeArray(to_send)
        self.send(SystemFunctions.encodeArray([to_send]))
        
        

        #response = self.receive()
        self.sock.close()


    def connect(self, host, port):
        self.sock.connect((host, port))


    def send(self, msg):
        totalsent = 0
        msglen = len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                self.sock.close()
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


class ClientConnection(Thread):

    def __init__(self, socket, address, identifier, parameters):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.identifier = identifier
        self.parameters = parameters
        self.start()


    def run(self):
        try:
            response = self.receive()
            resp_array = SystemFunctions.decodeArray(response)

            rA = resp_array[0]
            id_A = resp_array[1]

            rB = get_random_bytes(16)

            cli2ser = Client2Server(None, self.identifier, None, CONNECTION_PARAMS['SERVER_HOST'], CONNECTION_PARAMS['SERVER_PORT'], 
                                        param, None, None)
        
            cli2ser.third_party(id_A, rA, rB)

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


class ClientListen(Thread):

    def __init__(self, host, port, identifier, parameters):
        Thread.__init__(self)
        self.host = host
        self.port = port
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.identifier = identifier
        self.parameters = parameters
        self.stop_ = False


    def stop(self):
        self.stop_ = True
        stop_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stop_sock.connect((self.host, self.port))
        stop_sock.close()


    def run(self):
        self.serversocket.bind((self.host, self.port))
        self.serversocket.listen(40)

        print(f'Client Listening on {self.port}')
        
        # Wait for Clients
        while not self.stop_:
            clientsocket, address = self.serversocket.accept()
            if not self.stop_:
                ClientConnection(socket=clientsocket, address=address, identifier=self.identifier, parameters=param)
        print('Cliend Stopped Listening')


if __name__ == '__main__':
    # Create Parameters Set
    xa = POINT_PARAMS['xA']
    ya = POINT_PARAMS['yA']
    xb = POINT_PARAMS['xB']
    yb = POINT_PARAMS['yB']

    param = Parameters(xa, ya, xb, yb)

    # Create Client Folder if not Exists
    path = '.client'
    if not os.path.exists(path):
        os.makedirs(path)
    
    identifier = input('Identifier: ')

    listen_port = int(input('Ingrese el puerto para escuchar: '))
    listening = ClientListen(host='127.0.0.1', port=listen_port, identifier=identifier, parameters=param)
    listening.start()

    # Create Client Secret File if not Exists
    filepath = os.path.join(path, f'{identifier}.json')
    if not os.path.exists(filepath):
        with open(filepath, 'w') as f:
            json.dump({}, f)
    
    # Check if there is no pre-register
    with open(filepath) as f:
        secrets_ = json.load(f)

    preregistered = True
    if secrets_.get('pi_0') is None or secrets_.get('pi_1') is None:
        pw = getpass('Password: ')
        client = Client2Server(None, identifier, pw, CONNECTION_PARAMS['SERVER_HOST'], CONNECTION_PARAMS['SERVER_PORT'], 
                                param, listening.host, listening.port)
        preregistered = client.preregister()

    # Connect to Server
    if preregistered:
        exit_ = True
        while exit_:
            conn_s = input('Connect to Server (type yes/no): ')
            while conn_s != 'yes' and conn_s != 'no':
                conn_s = input('Connect to Server (type yes/no): ')
            if conn_s == 'yes':
                client = Client2Server(None, identifier, None, CONNECTION_PARAMS['SERVER_HOST'], CONNECTION_PARAMS['SERVER_PORT'], 
                                        param, listening.host, listening.port)
                client.run()
            else:
                conn_c = input('Connect to Client (type yes/no): ')
                while conn_c != 'yes' and conn_c != 'no':
                    conn_c = input('Connect to Server (type yes/no): ')
                if conn_c == 'yes':
                    client_host = input('Ingrese el host: ')
                    client_port = int(input('Ingrese el puerto: '))
                    client = Client2Client(None, identifier, None, client_host, client_port, param)
                    client.run()
                else:
                    exit_ = False
                    listening.stop()
