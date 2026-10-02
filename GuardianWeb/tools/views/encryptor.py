import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.http import HttpResponse
from django.shortcuts import render

SALT_SIZE = 16
PBKDF2_ITERATIONS = 480_000


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def file_encryptor(request):
    error = None

    if request.method == "POST":
        uploaded_file = request.FILES.get("file")
        password = request.POST.get("password", "")
        action = request.POST.get("action")

        if not uploaded_file:
            error = "Please choose a file."
        elif not password:
            error = "Please enter a password."
        else:
            file_bytes = uploaded_file.read()
            original_name = uploaded_file.name
            output_bytes = None
            output_name = None

            if action == "encrypt":
                salt = os.urandom(SALT_SIZE)
                key = derive_key(password, salt)
                fernet = Fernet(key)
                output_bytes = salt + fernet.encrypt(file_bytes)
                output_name = original_name + ".enc"

            elif action == "decrypt":
                if len(file_bytes) < SALT_SIZE:
                    error = "This doesn't look like a valid encrypted file."
                else:
                    salt, ciphertext = file_bytes[:SALT_SIZE], file_bytes[SALT_SIZE:]
                    key = derive_key(password, salt)
                    fernet = Fernet(key)
                    try:
                        output_bytes = fernet.decrypt(ciphertext)
                        output_name = (
                            original_name[:-4] if original_name.endswith(".enc") else original_name + ".dec"
                        )
                    except InvalidToken:
                        error = "Wrong password, or the file is corrupted."

            if output_bytes is not None and not error:
                response = HttpResponse(output_bytes, content_type="application/octet-stream")
                response["Content-Disposition"] = f'attachment; filename="{output_name}"'
                return response

    return render(request, "tools/encryptor.html", {"error": error})
