from Crypto.Hash import SHAKE256

class SystemFunctions:

    @staticmethod
    def Hi(byte_data, fixed_str='aa', n=256):
        h_256 = SHAKE256.new()
        f_str = bytes(fixed_str, 'utf-8')
        h_256.update(f_str)
        for byte_ in byte_data:
            h_256.update(byte_)
        return h_256.read(n)


    @staticmethod
    def encodeArray(arrays):
        L = []
        for array in arrays:
            lt = len(array)
            L.append(lt.to_bytes(4, byteorder='big') + array)
        return b''.join(L)


    @staticmethod
    def decodeArray(barr):        
        L = []
        i = 0
        while i < len(barr):
            n = int.from_bytes(barr[i:i + 4], byteorder='big')
            L.append(barr[i + 4:i + 4 + n])
            i = i + 4 + n
        return L