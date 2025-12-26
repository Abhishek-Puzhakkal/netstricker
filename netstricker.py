import argparse
from input_validater import IpRangeChecker

commands = argparse.ArgumentParser()

commands.add_argument("--discover")
user_input = commands.parse_args()

if user_input.discover:
    checker = IpRangeChecker(user_input.discover)
    if checker.checker():
        print(f'scanning started on {user_input.discover}')
    else:
        print(f'invalid user input {user_input.discover} is not valid ')



