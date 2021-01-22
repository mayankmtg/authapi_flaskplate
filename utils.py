#   Primary Author: Mayank Mohindra <mayankmohindra06@gmail.com>
#
#   Purpose: Utility helper methods and constants for api.py

import yaml

def load_yaml(filename: str) -> dict:
    try:
        with open(filename) as f:
            yaml_content = yaml.safe_load(f)
            return yaml_content
        return {}
    except:
        return {}
        

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
