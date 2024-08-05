import ctypes
from ctypes import c_char, c_int, c_char_p, c_void_p, Structure, POINTER, byref, create_string_buffer
from getpass import getpass

# Load the shared library
libdinamo = ctypes.CDLL('/usr/lib/libdinamo.so')

# Define constants
HOST_ADDR = "10.202.40.16"
USER_ID = ""
USER_PWD = ""
#USER_PWD = getpass("PASS: ")
KEY_ID = "Teste"
KEY_TYPE = 201  # ALG_3DES_168 in your specific context
FLAGS = 0x00000001 | 0x00000002  # EXPORTABLE_KEY | NO_CRYPTO

# Assuming these are the actual values
MAX_ADDR_LEN = 128
MAX_USR_LEN = 16
MAX_USR_PWD = 16
DEFAULT_PORT = 4433  # Replace with the actual default port value
SS_USER_PWD = 0x00000002  # Replace with the actual value
ENCRYPTED_CONN = 0x00000001  # Replace with the actual value
REMOVE_FROM_HCM = 0x00000020  # Replace with the actual value

# Define the AUTH_PWD structure

# Define the AUTH_PWD structure
class AUTH_PWD(Structure):
    _fields_ = [("szAddr", c_char * MAX_ADDR_LEN),
                ("nPort", c_int),
                ("szUserId", c_char * MAX_USR_LEN),
                ("szPassword", c_char * MAX_USR_PWD)]

class DinamoWrapper:
    def __init__(self):
        self.libdinamo = self._load_library()
        self.KEY_ID = KEY_ID
        self.KEY_TYPE = KEY_TYPE
        self.FLAGS = FLAGS

    def _load_library(self):
        """Carregar a biblioteca compartilhada Dinamo"""
        try:
            libdinamo = ctypes.CDLL('/usr/lib/libdinamo.so')
            return libdinamo
        except OSError as e:
            raise RuntimeError(f"Failed to load library: {e}")

    def initialize(self):
        """Inicializar a biblioteca Dinamo"""
        ret = self.libdinamo.DInitialize(0)
        if ret:
            raise RuntimeError(f"Dinamo initialization failed with code: {ret}")
        print("Bibliotecas inicializadas.")

    def open_session(self):
        """Abrir uma sessão"""
        authPwd = AUTH_PWD()
        authPwd.szAddr = (HOST_ADDR + '\0' * (MAX_ADDR_LEN - len(HOST_ADDR))).encode('utf-8')
        authPwd.nPort = DEFAULT_PORT
        authPwd.szUserId = (USER_ID + '\0' * (MAX_USR_LEN - len(USER_ID))).encode('utf-8')
        authPwd.szPassword = (USER_PWD + '\0' * (MAX_USR_PWD - len(USER_PWD))).encode('utf-8')

        hSession = c_void_p()
        ret = self.libdinamo.DOpenSession(byref(hSession), SS_USER_PWD, byref(authPwd), ctypes.sizeof(authPwd), ENCRYPTED_CONN)
        if ret:
            raise RuntimeError(f"Failed to open session with code: {ret}")
        print("Sessao com o Dinamo estabelecida.")
        return hSession

    def generate_key(self, session):
        """Gerar uma chave"""
        hKey = c_void_p()
        ret = self.libdinamo.DGenerateKey(session, self.KEY_ID.encode('utf-8'), self.KEY_TYPE, self.FLAGS, byref(hKey))
        if ret:
            raise RuntimeError(f"Failed to generate key with code: {ret}")
        print("Chave criada com sucesso.")
        return hKey

    def get_key_value(self, session, key_handle):
        """Obter o valor da chave gerada"""
        key_value_len = c_void_p()
        ret = self.libdinamo.DGetKeyValue(session, key_handle, None, byref(key_value_len))
        if ret:
            raise RuntimeError(f"Failed to get key value length with code: {ret}")

        key_value = (ctypes.c_ubyte * key_value_len.value)()
        ret = self.libdinamo.DGetKeyValue(session, key_handle, key_value, byref(key_value_len))
        if ret:
            raise RuntimeError(f"Failed to get key value with code: {ret}")

        return bytes(key_value)

    def close_session(self, session):
        """Encerrar a sessão"""
        if session:
            ret = self.libdinamo.DCloseSession(byref(session), 0)
            if ret:
                raise RuntimeError(f"Failed to close session with code: {ret}")
            print("Sessao encerrada.")

    def finalize(self):
        """Finalizar a biblioteca Dinamo"""
        self.libdinamo.DFinalize()
        print("Bibliotecas finalizada.")

# Define the function prototypes
libdinamo.DInitialize.argtypes = [c_int]
libdinamo.DInitialize.restype = c_int

libdinamo.DOpenSession.argtypes = [POINTER(c_void_p), c_int, POINTER(AUTH_PWD), c_int, c_int]
libdinamo.DOpenSession.restype = c_int

libdinamo.DGenerateKey.argtypes = [c_void_p, c_char_p, c_int, c_int, POINTER(c_void_p)]
libdinamo.DGenerateKey.restype = c_int

libdinamo.DDestroyKey.argtypes = [POINTER(c_void_p), c_int]
libdinamo.DDestroyKey.restype = c_int

libdinamo.DCloseSession.argtypes = [POINTER(c_void_p), c_int]
libdinamo.DCloseSession.restype = c_int

libdinamo.DFinalize.argtypes = []
libdinamo.DFinalize.restype = None

# Python function that wraps the main C function
def main():
    nRet = libdinamo.DInitialize(0)
    if nRet:
        print(f"Falha na funcao: DInitialize \nCodigo de erro: {nRet}")
        return nRet

    print("Bibliotecas inicializadas.")

    authPwd = AUTH_PWD()
    authPwd.szAddr = (HOST_ADDR + '\0' * (MAX_ADDR_LEN - len(HOST_ADDR))).encode('utf-8')
    authPwd.nPort = DEFAULT_PORT
    authPwd.szUserId = (USER_ID + '\0' * (MAX_USR_LEN - len(USER_ID))).encode('utf-8')
    authPwd.szPassword = (USER_PWD + '\0' * (MAX_USR_PWD - len(USER_PWD))).encode('utf-8')

    hSession = c_void_p()
    nRet = libdinamo.DOpenSession(byref(hSession), SS_USER_PWD, byref(authPwd), ctypes.sizeof(authPwd), ENCRYPTED_CONN)
    if nRet:
        print(f"Falha na funcao: DOpenSession \nCodigo de erro: {nRet}")
        return nRet
    # DGetUserKey
    print("Sessao com o Dinamo estabelecida.")
    hKey = c_void_p()
    nRet = libdinamo.DGenerateKey(hSession, KEY_ID.encode('utf-8'), KEY_TYPE, FLAGS, byref(hKey))
    if nRet:
        print(f"Falha na funcao: DGenerateKey \nCodigo de erro: {nRet}")
        return nRet

    print("Chave criada com sucesso.")
    phKey = c_void_p()
    nRet = libdinamo.DGetUserKey(hSession, KEY_ID.encode('utf-8'), 0, byref(phKey))

    # nRet = libdinamo.DDestroyKey(byref(phKey), REMOVE_FROM_HCM)
    # if nRet:
    #     print(f"Falha na funcao: DDestroyKey \nCodigo de erro: {nRet}")
    #     return nRet

    # print("Chave removida com sucesso.")

    # if hKey:
    #     libdinamo.DDestroyKey(byref(hKey), 0)
    #     print("Contexto da chave liberado.")

    if hSession:
        libdinamo.DCloseSession(byref(hSession), 0)
        print("Sessao encerrada.")

    libdinamo.DFinalize()
    print("Bibliotecas finalizada.")

    return nRet

# Run the main function
if __name__ == "__main__":
    main()

