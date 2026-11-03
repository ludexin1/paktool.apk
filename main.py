"""
PAK TOOL - Android APK (Kivy)
tool.py mantığı gömülü. gmalg yerine saf Python ZUC. C derleme yok.
"""
import os, sys, struct, shutil, zlib, math, itertools as it
from pathlib import Path, PurePath
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.clock import Clock
from kivy.utils import platform

from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_CBC
from Crypto.Hash import SHA1
from Crypto.Util.Padding import unpad
from zstandard import ZstdDecompressor, ZstdCompressionDict, DICT_TYPE_AUTO, ZstdCompressor

# ============================================================
# STORAGE
# ============================================================
def get_base_dir():
    if platform == 'android':
        try:
            from android.storage import primary_external_storage_path
            base = Path(primary_external_storage_path()) / "PAK_TOOL"
        except Exception:
            base = Path("/sdcard/PAK_TOOL")
    else:
        base = Path(__file__).resolve().parent / "PAK_TOOL"
    base.mkdir(parents=True, exist_ok=True)
    return base

BASE_DIR = get_base_dir()

def ensure_dirs():
    for d in ["PAK", "EDIT", "UNPACK", "RESULT"]:
        (BASE_DIR / d).mkdir(exist_ok=True)

# ============================================================
# PURE PYTHON ZUC
# ============================================================
class ZUC:
    _D = [0x44D7,0x26BC,0x626B,0x135E,0x5789,0x35E2,0x7135,0x09AF,
          0x4D78,0x2F13,0x6BC4,0x1AF1,0x5E26,0x3C4D,0x789A,0x47AC]
    _S0 = bytes([
        0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,
        0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,
        0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,
        0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,
        0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,
        0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,
        0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,
        0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,
        0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,
        0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,
        0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,
        0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,
        0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,
        0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,
        0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,
        0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60])
    _S1 = bytes([
        0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,
        0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,
        0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,
        0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,
        0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,
        0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,
        0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,
        0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,
        0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,
        0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,
        0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,
        0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,
        0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,
        0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,
        0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,
        0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2])

    def __init__(self, key, iv):
        self.S = [(key[i] << 23) | (self._D[i] << 8) | iv[i] for i in range(16)]
        self.R1 = self.R2 = 0
        self.X = [0, 0, 0, 0]
        self._init()

    @staticmethod
    def _add(a, b):
        c = a + b
        return (c & 0x7FFFFFFF) + (c >> 31)

    @staticmethod
    def _rot(x, k):
        return ((x << k) | (x >> (31 - k))) & 0x7FFFFFFF

    @staticmethod
    def _S(x):
        a, b, c, d = (x>>24)&255, (x>>16)&255, (x>>8)&255, x&255
        return ((ZUC._S0[a] << 24) | (ZUC._S1[b] << 16) | (ZUC._S0[c] << 8) | ZUC._S1[d]) & 0xFFFFFFFF

    @staticmethod
    def _L1(X): return (X ^ ZUC._rot(X,2) ^ ZUC._rot(X,10) ^ ZUC._rot(X,18) ^ ZUC._rot(X,24)) & 0xFFFFFFFF
    @staticmethod
    def _L2(X): return (X ^ ZUC._rot(X,8) ^ ZUC._rot(X,14) ^ ZUC._rot(X,22) ^ ZUC._rot(X,30)) & 0xFFFFFFFF

    def _br(self):
        X = self.X
        X[0] = ((X[0]&0x7FFF8000)<<1) | (X[1]&0xFFFF)
        X[1] = ((X[1]&0x7FFF8000)<<1) | (X[2]&0xFFFF)
        X[2] = ((X[2]&0x7FFF8000)<<1) | (X[3]&0xFFFF)
        X[3] = ((X[3]&0x7FFF8000)<<1) | (X[0]&0xFFFF)

    def _F(self):
        X = self.X
        W = ((X[0] ^ self.R1) + self.R2) & 0xFFFFFFFF
        W1 = (self.R1 + X[1]) & 0xFFFFFFFF
        W2 = self.R2 ^ X[2]
        u = self._L1(((W>>16)&0xFFFF) | ((W1>>16)<<16) | ((W2&0xFFFF)<<16))
        return u

    def _lfsr_init(self):
        S = self.S
        v = S[0]
        u = self._F()
        S[0] = self._add(S[0], self._rot(S[0], 8))
        S[0] ^= self._rot(S[4], 20) ^ self._rot(S[10], 21) ^ self._rot(S[13], 17) ^ self._rot(S[15], 15)
        S[0] = self._add(S[0], u)
        for i in range(15): S[i] = S[i+1]
        S[15] = v

    def _lfsr_work(self):
        S = self.S
        v = S[0]
        S[0] = self._add(S[0], self._rot(S[0], 8))
        S[0] ^= self._rot(S[4], 20) ^ self._rot(S[10], 21) ^ self._rot(S[13], 17) ^ self._rot(S[15], 15)
        for i in range(15): S[i] = S[i+1]
        S[15] = v

    def _init(self):
        for _ in range(32):
            self._br(); self._lfsr_init()
            self.R1, self.R2 = self.R2, self._F()
        self._br(); self._lfsr_work()
        self.R1, self.R2 = self.R2, self._F()

    def gen_word(self):
        self._br()
        z = self._F() ^ self.X[3]
        self._lfsr_work()
        self.R1, self.R2 = self.R2, self._F()
        return z

def zuc_keystream():
    z = ZUC(bytes.fromhex('01010101010101010101010101010101'),
            bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'))
    return [z.gen_word() for _ in range(16)]

# ============================================================
# SM4 (pure python)
# ============================================================
class SM4:
    _S = bytes([
        52,102,37,116,137,120,228,169,90,65,188,122,214,22,33,35,77,97,218,148,155,223,19,60,
        105,58,49,10,95,215,153,149,241,174,114,61,7,96,36,182,152,238,196,162,45,136,221,141,
        4,234,187,17,202,62,93,161,246,63,176,151,128,71,43,166,230,247,217,177,89,192,124,190,
        84,40,183,126,79,248,67,110,160,80,14,245,144,184,251,163,123,98,25,70,3,42,185,143,
        159,119,180,91,131,135,8,235,226,30,66,240,15,232,113,106,117,173,85,31,181,171,51,250,
        127,21,189,133,216,6,104,179,82,48,72,11,0,237,239,178,87,142,231,108,213,229,46,83,
        130,5,249,129,244,86,191,140,75,227,219,74,145,76,44,211,64,41,78,32,20,54,121,9,
        111,209,55,224,57,12,138,146,56,18,53,109,225,253,147,154,23,212,201,156,107,132,38,157,
        175,118,193,158,208,150,197,203,233,115,73,210,205,100,195,199,1,125,243,172,252,222,164,68,
        50,27,194,186,28,2,198,39,69,139,242,24,167,16,81,29,200,207,99,255,47,13,88,206,
        101,165,220,26,59,134,254,34,92,168,94,103,170,236,112,204])
    _FK = [1184304796,1270900830,1493524870,3164752158]
    _CK = [964907,973793155,2654690407,2916866751,2071233739,1226140771,3348805095,2045549823,
           388349611,800627875,612403927,3721562911,1195432523,3150178931,612053223,2445162591,
           67183755,1174197155,1393249511,3331183455,3822152747,1332317203,1804781383,1990130463,
           1282653851,3376591251,2910902311,925872959,332098219,735840931,396665415,3588844719]

    @staticmethod
    def _rol(x, n): return (x << n) & 0xFFFFFFFF | (x >> (32 - n))
    @staticmethod
    def _bs(X):
        S = SM4._S
        return (S[X>>24&255]<<24 | S[X>>16&255]<<16 | S[X>>8&255]<<8 | S[X&255])
    @staticmethod
    def _t0(X):
        X = SM4._bs(X)
        return X ^ SM4._rol(X,2) ^ SM4._rol(X,10) ^ SM4._rol(X,18) ^ SM4._rol(X,24)
    @staticmethod
    def _t1(X):
        X = SM4._bs(X)
        return X ^ SM4._rol(X,13) ^ SM4._rol(X,23)
    @staticmethod
    def _expand(key, rk):
        K = [int.from_bytes(key[i*4:i*4+4], 'big') ^ SM4._FK[i] for i in range(4)]
        for i in range(32):
            t = SM4._t1(K[1]^K[2]^K[3]^SM4._CK[i])
            new = K[0] ^ t
            K = [K[1], K[2], K[3], new]
            rk[i] = new

    def __init__(self, key):
        self._rk = [0]*32
        SM4._expand(key, self._rk)

    def _crypt(self, data, rk):
        out = bytearray()
        for off in range(0, len(data), 16):
            X = list(struct.unpack_from('>IIII', data, off))
            for i in range(0, 32, 4):
                X[0] ^= SM4._t0(X[1]^X[2]^X[3]^rk[i])
                X[1] ^= SM4._t0(X[2]^X[3]^X[0]^rk[i+1])
                X[2] ^= SM4._t0(X[3]^X[0]^X[1]^rk[i+2])
                X[3] ^= SM4._t0(X[0]^X[1]^X[2]^rk[i+3])
            out += struct.pack('>IIII', X[3], X[2], X[1], X[0])
        return bytes(out)

    def encrypt_bulk(self, data): return self._crypt(data, self._rk)
    def decrypt_bulk(self, data): return self._crypt(data, self._rk[::-1])

# ============================================================
# PAK SABİTLERİ
# ============================================================
RSA_MOD_1 = bytes.fromhex('CBE8B9F2504050EF9831B719E9A6249A6D238505ADE909BDE78C180DED6072A0C3347B8AF4780E1F212D952D82D4BF7F233C1ECA499E1F9D9A85B4FAD759F54BABC1666C5DE411EA9E4B2374425DD6C6F54333BBC8F2610FE6063E4D0D6C21A671A8F7C3740555E5DC06D4E1691C456DB4116C0C012BF7B206E8311AAAEC689952BF804EF638F09D5822B4117B114208F14DEB459E80CB770E5B0D7978E21F5E6CED4999D3583108221A7AB28B960277ADB5690A332784019D9C195BE4EA9EA0A09459010F236465DE0D59C3EF7324E954E1118D93EE19F299760C2CDB963CE87973EA5ECC9BBE81C27D4C7C8572AC07E9BCEAC9BD72AB7A56A3C0AD736ABCE4')

SIMPLE1_KEY = 121
SIMPLE2_KEY = bytes.fromhex('E55B4ED1')
SIMPLE2_BS = 16
SM4_S4 = 'eb691efea914241317a8'
SM4_S2 = 'Q0hVTKey$as*1ZFlQCiA'
SM4_SN = ['xG2qW5lP7lV2iN5fN5pG','xT1cJ6dL5wC0kK1rB4dK','qC4jS5bZ6fL5xE6nD4zA','gD4jQ2aL3bS3lC3xT0iW',
    'xU1yQ8wE9zY3gZ3bT5aE','uQ3cO2dX7xY4xU7gH7iS','gW1fR0jK6wQ4oN0oK1kZ','aJ4pV7iZ7pU4wP2aC2cZ',
    'cX6jT3cM2oT3vK0kJ1qN','iT2vS0cS6yT6cZ1sE1lO','hM1pH9iY8wM9hT4lN5uJ','kG6bC8jK0fL0dE4sH4mL',
    'dB6lB3vE0eZ8wM8rI0aC','tP7sP7nI9rA2vQ4cV5yQ','aT0cL1yN4pT3sZ7eM2vY','uV6fU8fC9zN3mP5dH8mN',
    'rT6aQ6oZ1yM0gO5tO1aN','jU5bH7lQ0fM9hK2kI0oF','iQ0eM0mJ7uT0kV6kL5zY']
EM_S1=1; EM_S2=16; EM_SM4_2=2; EM_SM4_4=4; EM_SM4_NEW=31; EM_SM4_MASK=~31
CM_NONE=0; CM_ZLIB=1; CM_ZSTD=6; CM_ZSTD_DICT=8; CM_MASK=15

class Misc:
    @staticmethod
    def pad4(d):
        p = 4 - len(d) % 4
        return d if p == 4 else d + b'\x00'*p
    @staticmethod
    def up(x, n): return (x + n - 1) // n * n

class Reader:
    def __init__(self, buf, cur=0):
        self._b = buf; self._c = cur
    def u1(self): return self.unpack('B')[0]
    def u4(self): return self.unpack('<I')[0]
    def u8(self): return self.unpack('<Q')[0]
    def i4(self): return self.unpack('<i')[0]
    def s(self, n): return self.unpack(f'{n}s')[0]
    def unpack(self, f, off=0, mv=True):
        x = struct.unpack_from(f, self._b, self._c + off)
        if mv: self._c += struct.calcsize(f)
        return x
    def string(self):
        L = self.i4()
        if L == 0: return ''
        return self.unpack(f'{L}s')[0].rstrip(b'\x00').decode()

class PakInfo:
    def __init__(self, buf, ks):
        r = Reader(buf[-45:])
        self.index_encrypted = (r.u1() ^ (ks[3] & 0xFF)) == 1
        self.magic = r.u4() ^ ks[2]
        self.version = r.u4()
        k = struct.pack('<5I', *ks[4:9])
        self.index_hash = bytes(a^b for a,b in zip(r.s(20), k)) if self.version >= 6 else b''
        self.index_size = r.u8() ^ ((ks[10]<<32)|ks[11])
        self.index_offset = r.u8() ^ ((ks[0]<<32)|ks[1])
        if self.version <= 3: self.index_encrypted = False

class TencentPakInfo(PakInfo):
    def __init__(self, buf, ks):
        super().__init__(buf, ks)
        r = Reader(buf[-self._mem(self.version):])
        k8 = struct.pack('<8I', *ks[7:15])
        self.unk1 = bytes(a^b for a,b in zip(r.s(32), k8)) if self.version >= 7 else b''
        self.packed_key = r.s(256) if self.version >= 8 else b''
        self.packed_iv = r.s(256) if self.version >= 8 else b''
        self.packed_index_hash = r.s(256) if self.version >= 8 else b''
        self.stem_hash = r.u4() ^ ks[8] if self.version >= 9 else 0
        self.unk2 = r.u4() ^ ks[9] if self.version >= 9 else 0
        self.content_org_hash = r.s(20) if self.version >= 12 else b''
    @staticmethod
    def _mem(v): return 45 + (32 if v>=7 else 0) + (768 if v>=8 else 0) + (8 if v>=9 else 0) + (20 if v>=12 else 0)

class PakBlk:
    def __init__(self, r):
        self.start = r.u8(); self.end = r.u8()

@dataclass
class PakEntry:
    def __init__(self, r, v):
        self.content_hash = r.s(20)
        if v <= 1: _ = r.u8()
        self.offset = r.u8()
        self.uncompressed_size = r.u8()
        self.compression_method = r.u4() & CM_MASK
        self.size = r.u8()
        self.unk1 = r.u1() if v >= 5 else 0
        self.unk2 = r.s(20) if v >= 5 else b''
        if self.compression_method != 0 and v >= 3:
            self.compressed_blocks = [PakBlk(r) for _ in range(r.u4())]
        else:
            self.compressed_blocks = []
        self.compression_block_size = r.u4() if v >= 4 else 0
        self.encrypted = r.u1() == 1 if v >= 4 else False
        self.encryption_method = r.u4() if v >= 12 else 0
        self.index_new_sep = r.u4() if v >= 12 else 0

class PakCrypto:
    @staticmethod
    def rsa_extract(sig, mod):
        c = int.from_bytes(sig, 'little')
        n = int.from_bytes(mod, 'little')
        m = pow(c, 65537, n).to_bytes(256, 'little').rstrip(b'\x00')
        return PakCrypto._meow(Misc.pad4(m))
    @staticmethod
    def _xx(buf, x): return bytes(buf[i] ^ x[i%len(x)] for i in range(len(buf)))
    @staticmethod
    def _hh(buf, n):
        r = b''
        for _ in range(math.ceil(n/SHA1.digest_size)): r += SHA1.new(buf).digest()
        return r[:n] if len(r)>=n else r + b'\x00'*(n-len(r))
    @staticmethod
    def _meow(buf):
        def unp(x):
            skip = 1 + next((i for i in range(len(x)) if x[i]!=0))
            return x[skip:]
        if len(buf) < 43: return b''
        x1 = buf[1:][:SHA1.digest_size]; x2 = buf[SHA1.digest_size+1:]
        x1 = PakCrypto._xx(x1, PakCrypto._hh(x2, len(x1)))
        x2 = PakCrypto._xx(x2, PakCrypto._hh(x1, len(x2)))
        p1, m = x2[:SHA1.digest_size], x2[SHA1.digest_size:]
        return unp(m) if p1 == SHA1.new(b'\x00'*SHA1.digest_size).digest() else b''
    @staticmethod
    def dec_s1(c): return bytes(x ^ SIMPLE1_KEY for x in c)
    @staticmethod
    def dec_s2(c):
        key, = struct.unpack('<I', SIMPLE2_KEY)
        v = key; out = []
        for x, in struct.iter_unpack('<I', c):
            v ^= x; out.append(v)
        return struct.pack(f'<{len(out)}I', *out)
    @staticmethod
    @lru_cache(maxsize=1)
    def derive_key(fp, em):
        p1 = fp.stem.lower()
        if em == EM_SM4_2: secret = SM4_S2
        elif em == EM_SM4_4: secret = SM4_S4
        else: secret = f'{SM4_SN[(em-EM_SM4_NEW)%len(SM4_SN)]}{em}'
        return SHA1.new(str(p1+secret).encode()).digest()[:16]
    @staticmethod
    def dec_index(c, info):
        if info.version > 7:
            k = PakCrypto.rsa_extract(info.packed_key, RSA_MOD_1)
            iv = PakCrypto.rsa_extract(info.packed_iv, RSA_MOD_1)
            return unpad(AES.new(k, MODE_CBC, iv[:16]).decrypt(c), 16)
        return PakCrypto.dec_s1(c)
    @staticmethod
    def is_s1(em): return em == EM_S1
    @staticmethod
    def is_s2(em): return em in (EM_S2, 17)
    @staticmethod
    def is_sm4(em): return em in (EM_SM4_2, EM_SM4_4) or (em & EM_SM4_MASK) != 0
    @staticmethod
    def align(n, em):
        if PakCrypto.is_s2(em): return Misc.up(n, SIMPLE2_BS)
        if PakCrypto.is_sm4(em): return Misc.up(n, 16)
        return n
    @staticmethod
    def dec_block(c, fp, em):
        if PakCrypto.is_s1(em): return PakCrypto.dec_s1(c)
        if PakCrypto.is_s2(em): return PakCrypto.dec_s2(c)
        if PakCrypto.is_sm4(em): return SM4(PakCrypto.derive_key(fp, em)).decrypt_bulk(c)
        raise ValueError(f'Unknown encryption: {em}')
    @staticmethod
    @lru_cache(maxsize=33)
    def block_indices(n, em):
        if not PakCrypto.is_sm4(em): return list(range(n))
        perm = []; state = n
        while len(perm) != n:
            x1 = ((1103515245 * state) & 0xFFFFFFFF)
            if x1 & 0x80000000: x1 = ((x1 + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            state = (x1 + 12345) & 0xFFFFFFFF
            if state & 0x80000000: state = ((state + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            x2 = ((x1 + 77880) & 0xFFFFFFFF) if state < 0 else state
            v = ((x2 >> 16) & 0xFFFFFFFF) % 32767
            v %= n
            if v not in perm: perm.append(v)
        inv = [0]*len(perm)
        for i, x in enumerate(perm): inv[x] = i
        return inv

class PakComp:
    @staticmethod
    @lru_cache(maxsize=33)
    def _zd(d): return ZstdDecompressor(d)
    @staticmethod
    def zstd_dict(data): return ZstdCompressionDict(data, DICT_TYPE_AUTO)
    @staticmethod
    def decomp(b, d, cm):
        if cm == CM_ZLIB:
            try: return zlib.decompress(b)
            except: return b
        if cm in (CM_ZSTD, CM_ZSTD_DICT):
            return PakComp._zd(d if cm == CM_ZSTD_DICT else None).decompress(b)
        raise ValueError(f'Unknown comp: {cm}')

class TencentPakFile:
    def __init__(self, fp):
        self._fp = PurePath(fp)
        with open(fp, 'rb') as f: self._fc = memoryview(f.read())
        self._mp = PurePath()
        self._zstd = 'zsdic' in str(self._fp)
        self._dict = None
        self._dict_entry = None
        self._files = []
        self._index = {}
        self._info = TencentPakInfo(self._fc, zuc_keystream())
        self._load()
    def _load(self):
        data = self._fc[self._info.index_offset:][:self._info.index_size]
        if self._info.index_encrypted:
            data = PakCrypto.dec_index(data, self._info)
        r = Reader(data)
        self._mp = PurePath()
        for p in PurePath(r.string()).parts:
            if p != '..': self._mp /= p
        self._files = [PakEntry(r, self._info.version) for _ in range(r.u4())]
        for _ in range(r.u8()):
            dp = PurePath(r.string())
            e = {r.string(): self._files[~r.i4()] for _ in range(r.u8())}
            if self._zstd and dp.name == 'zstddic':
                for v in e.values():
                    self._dict_entry = v
                    rr = Reader(self._fc[v.offset:][:v.size])
                    ds = rr.u8(); _ = rr.u4()
                    self._dict = PakComp.zstd_dict(rr.s(ds))
                    break
            else:
                self._index[dp] = e
    def _peek(self, off, sz, em):
        return self._fc[off:][:PakCrypto.align(sz, em)]
    def _peek_b(self, blk, em):
        return self._fc[blk.start:][:PakCrypto.align(blk.end - blk.start, em)]
    def dump(self, out, log_cb=None):
        out = out / self._mp
        out.mkdir(parents=True, exist_ok=True)
        for dp, dc in self._index.items():
            cur = out / dp
            cur.mkdir(parents=True, exist_ok=True)
            for name, e in dc.items():
                self._write(cur / name, e, log_cb)
    def _write(self, p, e, cb=None):
        em, cm = e.encryption_method, e.compression_method
        if cb: cb(f"→ {p.name}")
        with open(p, 'wb') as f:
            if cm == CM_NONE:
                d = self._peek(e.offset, e.size, em)
                if e.encrypted: d = PakCrypto.dec_block(d, p, em)
                f.write(d[:e.uncompressed_size]); return
            for x in PakCrypto.block_indices(len(e.compressed_blocks), em):
                d = self._peek_b(e.compressed_blocks[x], em)
                if e.encrypted: d = PakCrypto.dec_block(d, p, em)
                f.write(PakComp.decomp(d, self._dict, cm))

# ============================================================
# KIVY UI
# ============================================================
class MainScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.log_lines = []
        root = BoxLayout(orientation='vertical', padding=10, spacing=8)
        root.add_widget(Label(text="[b]PAK TOOL[/b]", markup=True, size_hint=(1,0.07),
                              font_size='22sp', color=(0,1,0.53,1)))
        root.add_widget(Label(text=f"Klasör: {BASE_DIR}", size_hint=(1,0.04), font_size='10sp',
                              color=(0.6,0.7,0.8,1)))
        self.pak_spinner = Spinner(text="PAK seç...", values=[], size_hint=(1,0.08))
        root.add_widget(self.pak_spinner)
        btns = BoxLayout(size_hint=(1,0.35), spacing=6, orientation='vertical')
        for txt, fn in [("1. UNPACK", self.do_unpack),
                        ("2. INJECT (yakında)", self.noop),
                        ("3. REPACK (yakında)", self.noop),
                        ("4. REPACK PATH (yakında)", self.noop),
                        ("5. PROTECT (yakında)", self.noop),
                        ("6. DELETE FOLDER", self.do_delete)]:
            btns.add_widget(Button(text=txt, on_press=fn))
        root.add_widget(btns)
        root.add_widget(Label(text="[b]LOG[/b]", markup=True, size_hint=(1,0.04)))
        self.log_view = TextInput(text='', readonly=True, size_hint=(1,0.40),
                                  background_color=(0.02,0.02,0.04,1),
                                  foreground_color=(0,1,0.53,1), font_size='10sp')
        root.add_widget(self.log_view)
        self.add_widget(root)
        Clock.schedule_interval(self.refresh, 3)

    def log(self, m):
        self.log_lines.append(m)
        if len(self.log_lines) > 300: self.log_lines = self.log_lines[-300:]
        self.log_view.text = '\n'.join(self.log_lines)
        self.log_view.cursor = (0, len(self.log_view.text))

    def refresh(self, dt):
        try:
            ensure_dirs()
            paks = sorted([p.name for p in (BASE_DIR/"PAK").glob('*.pak')])
            self.pak_spinner.values = paks
            if not paks: self.pak_spinner.text = "PAK klasörü boş"
        except Exception as e: self.log(f"refresh: {e}")

    def noop(self, *_):
        self.log("⚠ Bu işlem ileride eklenecek (şu an UNPACK çalışıyor)")

    def do_unpack(self, *_):
        name = self.pak_spinner.text
        if not name or name.startswith("PAK") or name == "PAK klasörü boş":
            self.log("❌ Önce PAK seç"); return
        path = BASE_DIR/"PAK"/name
        if not path.exists():
            self.log(f"❌ Bulunamadı: {path}"); return
        self.log(f"🚀 Unpack: {name}")
        import threading
        def job():
            try:
                pak = TencentPakFile(path)
                out = BASE_DIR/"UNPACK"/path.stem
                pak.dump(out, log_cb=lambda m: Clock.schedule_once(lambda dt: self.log(m)))
                Clock.schedule_once(lambda dt: self.log(f"✅ Bitti: {out}"))
            except Exception as e:
                import traceback
                Clock.schedule_once(lambda dt: self.log(f"❌ HATA: {e}\n{traceback.format_exc()}"))
        threading.Thread(target=job, daemon=True).start()

    def do_delete(self, *_):
        box = BoxLayout(orientation='vertical', padding=10, spacing=8)
        ti = TextInput(hint_text="silinecek klasör adı (UNPACK, RESULT vs. hariç)", size_hint=(1,0.3))
        box.add_widget(ti)
        popup = Popup(title="Klasör Sil", content=box, size_hint=(0.85,0.4))
        def ok(*_):
            n = ti.text.strip()
            if not n or '/' in n or '\\' in n or '..' in n:
                self.log("❌ Geçersiz"); popup.dismiss(); return
            t = BASE_DIR/n
            if t.exists() and t.is_dir() and n not in {'PAK','EDIT','UNPACK','RESULT'}:
                shutil.rmtree(t); self.log(f"✅ Silindi: {n}")
            else: self.log(f"❌ Silinemez: {n}")
            popup.dismiss()
        box.add_widget(Button(text="SİL", on_press=ok, size_hint=(1,0.2)))
        popup.open()

class PakApp(App):
    def build(self):
        ensure_dirs()
        sm = ScreenManager()
        sm.add_widget(MainScreen(name='main'))
        return sm
    def on_start(self):
        if platform == 'android':
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
            except: pass

if __name__ == '__main__':
    PakApp().run()
