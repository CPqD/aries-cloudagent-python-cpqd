"""Low-level interaction with the anoncreds library."""
# Para mais informacoes sobre as APIs consulte: /usr/include/dinamo.h
import json
import logging
import os
import sys
from ctypes import (
    Array,
    CDLL,
    POINTER,
    Structure,
    addressof,
    byref,
    c_int,
    cast,
    c_char,
    c_char_p,
    c_int8,
    c_int64,
    c_int32,
    c_size_t,
    c_ubyte,
    c_void_p,
    pointer,
    sizeof,
)
from ctypes.util import find_library
from io import BytesIO
from typing import Iterable, Optional, Mapping, Sequence, Tuple, Union, Callable, Any
from weakref import finalize

from .error import AnoncredsError, AnoncredsErrorCode


CALLBACKS = {}
LIB: Optional[CDLL] = None
LOGGER = logging.getLogger(__name__)


def _struct_dtor(ctype: Any, address: int, dtor: Callable):
    value = ctype.from_address(address)
    if value:
        dtor(value)

KEY_TYPE = 201  # ALG_ECX_ED25519
FLAGS = 0x00000001 | 0x00000002  # EXPORTABLE_KEY | NO_CRYPTO

MAX_ADDR_LEN = 128
MAX_USR_LEN = 16
MAX_USR_PWD = 16
DEFAULT_PORT = 4433  # Replace with the actual default port value
SS_USER_PWD = 0x00000002  # Replace with the actual value
ENCRYPTED_CONN = 0x00000001  # Replace with the actual value
REMOVE_FROM_HCM = 0x00000020  # Replace with the actual value

# Define the AUTH_PWD structure
class AUTH_PWD(Structure):
    _fields_ = [("szAddr", c_char * MAX_ADDR_LEN),
                ("nPort", c_int),
                ("szUserId", c_char * MAX_USR_LEN),
                ("szPassword", c_char * MAX_USR_PWD)]

# Define the function prototypes
# libdinamo.DInitialize.argtypes = [c_int]
# libdinamo.DInitialize.restype = c_int

# libdinamo.DOpenSession.argtypes = [POINTER(c_void_p), c_int, POINTER(AUTH_PWD), c_int, c_int]
# libdinamo.DOpenSession.restype = c_int

# libdinamo.DGenerateKey.argtypes = [c_void_p, c_char_p, c_int, c_int, POINTER(c_void_p)]
# libdinamo.DGenerateKey.restype = c_int

# libdinamo.DDestroyKey.argtypes = [POINTER(c_void_p), c_int]
# libdinamo.DDestroyKey.restype = c_int

# libdinamo.DCloseSession.argtypes = [POINTER(c_void_p), c_int]
# libdinamo.DCloseSession.restype = c_int

# libdinamo.DFinalize.argtypes = []
# libdinamo.DFinalize.restype = None


def finalize_struct(instance, ctype):
    """Attach a struct destructor."""
    finalize(
        instance, _struct_dtor, ctype, addressof(instance), instance.__class__._cleanup
    )


def keepalive(instance, *depend):
    """Ensure that dependencies are kept alive as long as the instance."""
    finalize(instance, lambda *_args: None, *depend)


class ObjectHandle(Structure):
    """Index of an active AnoncredsObject instance."""

    _fields_ = [
        ("value", c_int64),
    ]

    def __init__(self, value=0):
        """Initializer."""
        if isinstance(value, c_int64):
            value = value.value
        if not isinstance(value, int):
            raise ValueError("Invalid handle")
        super().__init__(value=value)
        finalize_struct(self, c_int64)

    @property
    def type_name(self) -> str:
        return object_get_type_name(self)

    def __repr__(self) -> str:
        """Format object handle as a string."""
        if self.value:
            try:
                type_name = f'"{self.type_name}"'
            except AnoncredsError:
                type_name = "<error>"
        else:
            type_name = "<none>"
        return f"{self.__class__.__name__}({type_name}, {self.value})"

    def __del__(self):
        object_free(self)

    @classmethod
    def _cleanup(cls, value: c_int64):
        """Destructor."""
        get_library().anoncreds_object_free(value)


class AnoncredsObject:
    """A generic Anoncreds object allocated by the library."""

    def __init__(self, handle: ObjectHandle) -> "AnoncredsObject":
        self.handle = handle

    def __bytes__(self) -> bytes:
        return bytes(self.to_json_buffer())

    def __repr__(self) -> str:
        """Format object as a string."""
        return f"{self.__class__.__name__}({self.handle.value})"

    def copy(self):
        return self.__class__(self.handle)

    def to_dict(self) -> dict:
        return json.load(BytesIO(self.to_json_buffer()))

    def to_json(self) -> str:
        return bytes(object_get_json(self.handle)).decode("utf-8")

    def to_json_buffer(self) -> memoryview:
        return object_get_json(self.handle).raw


class RawBuffer(Structure):
    """A byte buffer allocated by the library."""

    _fields_ = [
        ("len", c_int64),
        ("data", POINTER(c_ubyte)),
    ]

    def __bool__(self) -> bool:
        return bool(self.data)

    def __bytes__(self) -> bytes:
        if not self.len:
            return b""
        return bytes(self.array)

    def __len__(self) -> int:
        return int(self.len)

    @property
    def array(self) -> Array:
        return cast(self.data, POINTER(c_ubyte * self.len)).contents

    def __repr__(self) -> str:
        return f"<RawBuffer(len={self.len})>"


class ByteBuffer(Structure):
    """A managed byte buffer allocated by the library."""

    _fields_ = [("buffer", RawBuffer)]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        finalize_struct(self, RawBuffer)

    @property
    def _as_parameter_(self):
        return self.buffer

    @property
    def array(self) -> Array:
        return self.buffer.array

    @property
    def raw(self) -> memoryview:
        m = memoryview(self.array)
        keepalive(m, self)
        return m

    def __bytes__(self) -> bytes:
        return bytes(self.buffer)

    def __len__(self) -> int:
        return len(self.buffer)

    def __getitem__(self, idx) -> bytes:
        return bytes(self.buffer.array[idx])

    def __repr__(self) -> str:
        """Format byte buffer as a string."""
        return repr(bytes(self))

    @classmethod
    def _cleanup(cls, buffer: RawBuffer):
        """Call the byte buffer desctructor when this instance is released."""
        get_library().anoncreds_buffer_free(buffer)


def get_library() -> CDLL:
    """Return the CDLL instance, loading it if necessary."""
    global LIB
    if LIB is None:
        LIB = _load_library("dinamo")
        # do_call("anoncreds_set_default_logger")
    return LIB


class StrBuffer(Structure):
    """A string allocated by the library."""

    _fields_ = [("buffer", POINTER(c_char))]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        finalize_struct(self, c_char_p)

    def is_none(self) -> bool:
        """Check if the returned string pointer is null."""
        return not self.buffer

    def opt_str(self) -> Optional[str]:
        """Convert to an optional string."""
        val = self.value
        return val.decode("utf-8") if val is not None else None

    def __bool__(self) -> bool:
        return bool(self.buffer)

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        bval = self.value
        return bval if bval is not None else bytes()

    def __str__(self):
        """Convert to a string."""
        # not allowed to return None
        val = self.opt_str()
        return val if val is not None else ""

def library_version() -> str:
    """Get the version of the installed aries-askar library."""
    lib = get_library()
    lib.anoncreds_version.restype = c_void_p
    return str(StrBuffer(lib.anoncreds_version()))


def _load_library(lib_name: str) -> CDLL:
    """Load the CDLL library.
    The python module directory is searched first, followed by the usual
    library resolution for the current system.
    """
    lib_prefix_mapping = {"win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
    try:
        os_name = sys.platform
        lib_prefix = lib_prefix_mapping.get(os_name, "lib")
        lib_suffix = lib_suffix_mapping.get(os_name, ".so")
        lib_path = os.path.join(
            os.path.dirname(__file__), f"{lib_prefix}{lib_name}{lib_suffix}"
        )
        return CDLL(lib_path)
    except KeyError:
        LOGGER.debug("Unknown platform for shared library")
    except OSError as e:
        LOGGER.warning(e)
        LOGGER.warning("Library not loaded from python package")

    lib_path = find_library(lib_name)
    if not lib_path:
        raise AnoncredsError(
            AnoncredsErrorCode.WRAPPER, f"Library not found in path: {lib_path}"
        )
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise AnoncredsError(
            AnoncredsErrorCode.WRAPPER, f"Error loading library: {lib_path}"
        ) from e


def do_call(fn_name, *args):
    """Perform a synchronous library function call."""
    lib_fn = getattr(get_library(), fn_name)
    result = lib_fn(*args)
    # return result
    if result:
        raise get_current_error(True)


def get_current_error(expect: bool = False) -> Optional[AnoncredsError]:
    """
    Get the error result from the previous failed API method.

    Args:
        expect: Return a default error message if none is found
    """
    err_json = StrBuffer()
    if not get_library().anoncreds_get_current_error(byref(err_json)):
        try:
            msg = json.loads(err_json.value)
        except json.JSONDecodeError:
            LOGGER.warning("JSON decode error for anoncreds_get_current_error")
            msg = None
        if msg and "message" in msg and "code" in msg:
            return AnoncredsError(
                AnoncredsErrorCode(msg["code"]), msg["message"], msg.get("extra")
            )
        if not expect:
            return None
    return AnoncredsError(AnoncredsErrorCode.WRAPPER, "Unknown error")


def decode_str(value: c_char_p) -> str:
    return value.decode("utf-8")


def encode_str(arg: Optional[Union[str, bytes]]) -> c_char_p:
    """
    Encode an optional input argument as a string.

    Returns: None if the argument is None, otherwise the value encoded utf-8.
    """
    if arg is None:
        return c_char_p()
    if isinstance(arg, str):
        return c_char_p(arg.encode("utf-8"))
    return c_char_p(arg)


class FfiByteBuffer(Structure):
    """A byte buffer allocated by python."""

    _fields_ = [
        ("len", c_int64),
        ("value", POINTER(c_ubyte)),
    ]


def encode_bytes(arg: Optional[Union[str, bytes]]) -> FfiByteBuffer:
    buf = FfiByteBuffer()
    if isinstance(arg, memoryview):
        buf.len = arg.nbytes
        if arg.contiguous and not arg.readonly:
            buf.value = (c_ubyte * buf.len).from_buffer(arg.obj)
        else:
            buf.value = (c_ubyte * buf.len).from_buffer_copy(arg.obj)
    elif isinstance(arg, bytearray):
        buf.len = len(arg)
        buf.value = (c_ubyte * buf.len).from_buffer(arg)
    elif arg is not None:
        if isinstance(arg, str):
            arg = arg.encode("utf-8")
        buf.len = len(arg)
        buf.value = (c_ubyte * buf.len).from_buffer_copy(arg)
    return buf


def object_free(handle: ObjectHandle):
    get_library().anoncreds_object_free(handle)


def object_get_json(handle: ObjectHandle) -> ByteBuffer:
    result = ByteBuffer()
    do_call("anoncreds_object_get_json", handle, byref(result))
    return result


def object_get_type_name(handle: ObjectHandle) -> StrBuffer:
    result = StrBuffer()
    do_call("anoncreds_object_get_type_name", handle, byref(result))
    return result


def _object_from_json(method: str, value: Union[dict, str, bytes]) -> ObjectHandle:
    if isinstance(value, dict):
        value = json.dumps(value)
    result = ObjectHandle()
    do_call(method, encode_bytes(value), byref(result))
    return result


def _object_get_attribute(
    method: str, handle: ObjectHandle, name: str
) -> Optional[StrBuffer]:
    result = StrBuffer()
    do_call(method, handle, encode_str(name), byref(result))
    if result.is_none():
        result = None
    return result


def create_link_secret() -> str:
    result = StrBuffer()
    do_call(
        "anoncreds_create_link_secret",
        byref(result),
    )
    return str(result)

def merge_revocation_registry_deltas(
    rev_reg_delta_1: ObjectHandle,
    rev_reg_delta_2: ObjectHandle,
) -> ObjectHandle:
    rev_delta = ObjectHandle()
    do_call(
        "anoncreds_merge_revocation_registry_deltas",
        rev_reg_delta_1,
        rev_reg_delta_2,
        byref(rev_delta),
    )
    return rev_delta

def get_key(
    hSession: c_void_p,
    KEY_ID: str
):
    # DGetUserKey(hSession, KEY_ID.encode('utf-8'), 0, byref(phKey))
    phKey = c_void_p()
    do_call(
        "DGetUserKey",
        hSession, 
        KEY_ID.encode('utf-8'), 
        0, 
        byref(phKey)
    )
    return phKey

def destroy_key(
     hSession,
     KEY_ID: str  
):
    # DDestroyKey(byref(hKey), 0)
    phKey = get_key(hSession, KEY_ID)
    do_call(
        "DDestroyKey",
        byref(phKey),
        0
    )

def gen_key(
    hSession, 
    KEY_ID,
    KEY_TYPE, 
    FLAGS, 
):
    # DGenerateKey(hSession, KEY_ID.encode('utf-8'), KEY_TYPE, FLAGS, byref(hKey))
    hKey = c_void_p()
    do_call(
        "DGenerateKey",
        hSession, 
        KEY_ID.encode('utf-8'), 
        KEY_TYPE, 
        FLAGS, 
        byref(hKey)
    )
    return hKey

def sign():
    pass

def encrypt():
    pass

def verify():
    pass

def gen_hash(
        
):
    # type: 4
    # DSignHash(hHash, hKey, 0, NULL, &cbSignature);
    
    pass

def derive_key():
    pass

def do_connection(
        HOST_ADDR: str,
        USER_ID: str,
        USER_PWD: str
):
    authPwd = AUTH_PWD()
    authPwd.szAddr = (HOST_ADDR + '\0' * (MAX_ADDR_LEN - len(HOST_ADDR))).encode('utf-8')
    authPwd.nPort = DEFAULT_PORT
    authPwd.szUserId = (USER_ID + '\0' * (MAX_USR_LEN - len(USER_ID))).encode('utf-8')
    authPwd.szPassword = (USER_PWD + '\0' * (MAX_USR_PWD - len(USER_PWD))).encode('utf-8')

    hSession = c_void_p()
    # nRet = libdinamo.DOpenSession(byref(hSession), SS_USER_PWD, byref(authPwd), ctypes.sizeof(authPwd), ENCRYPTED_CONN)
    do_call(
        "DOpenSession",
        byref(hSession), 
        SS_USER_PWD, 
        byref(authPwd), 
        sizeof(authPwd), 
        ENCRYPTED_CONN
    )
    return hSession
