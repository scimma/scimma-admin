#!/usr/bin/env python

import argparse
from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
import sys

import boto3

def octal(value):
	try:
		return int(value, base=8)
	except:
		raise argparse.ArgumentTypeError(f"{value} is not an octal integer")

parser = argparse.ArgumentParser()
parser.add_argument("--permissions", help="Permissions to set on all ;mounted' files", type=octal, default="644")
parser.add_argument("secret_name", help="Name of secret", type=str)
parser.add_argument("mount_path", help="Path to the directory in which to 'mount' the secret contents", type=str)
args = parser.parse_args()

sm = boto3.client("secretsmanager", region_name="us-west-2")
sv = sm.get_secret_value(SecretId=args.secret_name)["SecretString"]
secret_data = json.loads(sv)

if not isinstance(secret_data, Mapping):
	print("Secret data is not a mapping", file=sys.stderr)
	exit(1)

basepath = Path(args.mount_path)
if not basepath.exists():
	basepath.mkdir(mode=args.permissions, parents=True)
for key, value in secret_data.items():
	filepath = basepath.joinpath(key)
	if not filepath.parent.exists():
		filepath.parent.mkdir(mode=args.permissions, parents=True)
	print(f"Creating {filepath} with mode {args.permissions}")
	# create the file with the correct permissions before we put data in it
	filepath.touch(mode=args.permissions, exist_ok=False)
	with open(filepath, 'w') as f:
		f.write(value)
