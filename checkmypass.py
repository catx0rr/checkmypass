#!/usr/bin/env python3

'''
    checkmypass.py - Secure password checker

        Security in obscurity. Trust no one.

        Why put your password in an online website that may contain javascript, capture it or
        process and store your password in the server?


        checkmypass:

        Its like your only providing the last 4 numbers of your social security number and
        provide only bits of information. The code will do the rest for you.
'''

import argparse
import hashlib
import requests
import sys


def open_file(passwd_file):

    # Check for file and convert list into tuple

    try:
        with open(passwd_file, mode='r') as pass_file:

            pass_list = [line.strip() for line in pass_file]

    except:
        raise FileNotFoundError('%s not found.' % passwd_file)
        sys.exit(1)

    else:
        return tuple(pass_list)
        pass_file.close()


def hash_password(password):

    # Hash the password

    encoded = password.encode('utf-8')

    sha1hash = hashlib.sha1(encoded).hexdigest().upper()

    return sha1hash


def prep_query(sha1hash):

    # slice the hashes to send the bits of data

    head = sha1hash[:5]

    return head


def return_query(sha1hash):

    # get the remaining hash and return the value

    tail = sha1hash[5:]

    return tail


def request_api_data(query):

    # Query the bits of password hash to the API
    url = 'https://api.pwnedpasswords.com/range/%s' % query

    # Check for response from the server
    response = requests.get(url)

    if response.status_code != 200:
        raise RuntimeError('Error fetching %s' % response.status_code)

    return response


def get_passwd_leak_count(hashes, selfhash):

    # Get the response.text from API and split the count and tail

    hashes = (line.split(':') for line in hashes.text.splitlines())

    # Check the tail of selfhash if it has a match
    for h, count in hashes:

        if h == selfhash:
            return count

    return 0


def pwn_checker(password_list):

    # Iterate over lists of passwords
    for password in password_list:

        # Convert the password into hash
        password_hash = hash_password(password)

        # Prepare the bits of data for processing
        head = prep_query(password_hash)
        tail = return_query(password_hash)

        # Request to the API for values
        response = request_api_data(head)

        # Get the values of pwn count
        pwn_count = get_passwd_leak_count(response, tail)
        print('Password "%s" has been pwned for %s times.' % (password, pwn_count))


def main():

    # Create a parser for arguments

    parser = argparse.ArgumentParser(
        description='Simple and secure password checker without compromising your own password.',
        allow_abbrev=False
    )

    parser.add_argument(
        '-l', '--list',
        metavar='',
        type=str,
        help='run program to a password list and check all of them if there are pwned passwords.'
    )

    parser.add_argument(
        '-p', '--password',
        metavar='',
        type=str,
        nargs='+',
        help='check password(s) if it is pwned how many times.'
    )

    args = parser.parse_args()

    if args.list:
        password_list = open_file(args.list)
        pwn_checker(password_list)
        sys.exit(0)

    if args.password:
        pwn_checker(args.password)
        sys.exit(0)

    else:
        print('"checkmypass.py -h" for usage.')
        sys.exit(0)


if __name__ == '__main__':
    main()
