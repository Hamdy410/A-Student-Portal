from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cs50 import SQL
from os import remove

# This file runs once and then removed

db = SQL("sqlite:///uni.db")
KEY = b"\xc1\xab\x14\t4\xefK[\xa8\xf0\xa6\xb4\xdb\xe1\xc0-"

# Please insert all the required data from this line
NATIONAL_ID = ""
FIRST_NAME = ""
SECOND_NAME = ""
NATIONALITY = ""
GENDER = ""  # F (female) or M (male)
RELIGION = ""
DATE_OF_BIRTH = ""  # Follows the format (MM-DD-YYYY)
COUNTRY_OF_BIRTH = ""
# To this line


db.execute(
    f"INSERT INTO admins (first_name, second_name, role, nationality, gender, religion, date_of_birth, country_of_birth) VALUES ({FIRST_NAME}, {SECOND_NAME}, 'Head Developer, {NATIONALITY}, 'M', {NATIONALITY}, {DATE_OF_BIRTH}, {NATIONALITY})"
)


cipher = AES.new(KEY, AES.MODE_GCM)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(pad(NATIONAL_ID.encode(), AES.block_size))
ciphertext = b64encode(ciphertext).decode()
nonce = b64encode(nonce).decode()
tag = b64encode(tag).decode()

db.execute(
    "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES('A2', ?, ?, ?, 'national_id')",
    ciphertext,
    nonce,
    tag,
)

remove("encrypt.py")
