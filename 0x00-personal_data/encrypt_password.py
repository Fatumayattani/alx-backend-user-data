#!/usr/bin/env python3
""" Encrypting passwords with bcrypt """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Hashes the input password using bcrypt.
    
    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: Salted and hashed password as a bytestring.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Checks if the provided password matches the hashed password.

    Args:
        hashed_password (bytes): The hashed password to be compared.
        password (str): The plain password to be checked.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
