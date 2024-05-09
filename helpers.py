from base64 import b64encode, b64decode
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from flask import redirect, render_template, session

# Constant key to be used in encrypting and decrypting data
KEY = b"\xc1\xab\x14\t4\xefK[\xa8\xf0\xa6\xb4\xdb\xe1\xc0-"


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def encrypt(plaintext):
    """Encrypts data using the AES technique"""
    cipher = AES.new(KEY, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext.encode(), AES.block_size))
    ciphertext = b64encode(ciphertext).decode()
    nonce = b64encode(nonce).decode()
    tag = b64encode(tag).decode()

    return {"ciphertext": ciphertext, "nonce": nonce, "tag": tag}


def decrypt(ciphertext, nonce, tag):
    """Decrypts data where it takes the ciphertext, the nonce and the tag"""
    try:
        ciphertext = b64decode(ciphertext)
        nonce = b64decode(nonce)
        tag = b64decode(tag)
        cipher = AES.new(KEY, AES.MODE_GCM, nonce)  # type: ignore
        decrypted_data = unpad(
            cipher.decrypt_and_verify(ciphertext, tag), AES.block_size
        )
        return decrypted_data.decode("utf-8")

    except ValueError:
        return None


def clean(s):
    """Terminates unneeded characters which are found in the IDENTITIES variable"""
    return s.replace(" ", "_").lower()
