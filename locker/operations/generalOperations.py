import base64

from cryptography.fernet import Fernet


def isPasswordStrong(password):
    if len(password) < 8:
        return False

    if not any(letter.isalpha() for letter in password):
        return False

    if not any(capital.isupper() for capital in password):
        return False

    if not any(number.isdigit() for number in password):
        return False

    return True


def encrypt(txt, secret):
    txt = str(txt)
    cipher_suite = Fernet(secret.key)
    encrypted_text = cipher_suite.encrypt(txt.encode('ascii'))
    encrypted_text = base64.urlsafe_b64encode(encrypted_text).decode("ascii")
    return encrypted_text


def decrypt(txt, secret):
    txt = base64.urlsafe_b64decode(txt)
    cipher_suite = Fernet(secret.key)
    decoded_text = cipher_suite.decrypt(txt).decode("ascii")
    return decoded_text
