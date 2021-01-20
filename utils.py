#   Primary Author: Mayank Mohindra <mayankmohindra06@gmail.com>
#
#   Purpose: Utility helper methods and constants for api.py


def message_dict(message: any) -> dict:
    returndict = {
        "message": message
    }
    return returndict

def return_dict(key: str, message: any) -> dict:
    returndict = {
        key: message
    }
    return returndict
