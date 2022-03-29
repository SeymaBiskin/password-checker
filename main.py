import requests
import hashlib
import sys


def check_if_pwned(response, hashed_password):
    result = (line.split(":") for line in response.text.splitlines())
    check_result = {password: count for password,
                    count in tuple(result) if password == hashed_password}
    if len(check_result) != 0:
        print(f"Password pwned {check_result[hashed_password]} times")
    else:
        print("Password is secure, not pwned")


def fetch_api_data(hashed_password):
    url = f"https://api.pwnedpasswords.com/range/{hashed_password}"
    return requests.get(url, verify=False)


def convert_to_sha1(password):
    sha1_password = hashlib.sha1(password.encode("UTF-8")).hexdigest().upper()
    first_5_char, tail = sha1_password[:5], sha1_password[5:]
    return first_5_char, tail, sha1_password

for password in sys.argv[1:]:
    first_five, tail, original = convert_to_sha1(password)
    api_response = fetch_api_data(first_five)
    check_if_pwned(api_response, tail)
