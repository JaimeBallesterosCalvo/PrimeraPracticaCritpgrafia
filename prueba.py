import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
salt = os.urandom(16)
# derive
kdf = Scrypt( #para guardar la contraseña y que sea resistente
    salt=salt, #almacena la clave y bits aleatorios 
    length=32, #longitud de la clave en BYTES
    n=2**14, #numero de iteraciones de derivación de las claves
    r=8, #tamaño de bloque que se utilizan en memoria
    p=1, #cuantas operaciones se hacen al mismo tiempo
)
key = kdf.derive(b"my great password")
# verify
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
kdf.verify(b"my great password", key)