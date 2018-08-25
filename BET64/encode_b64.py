#! /usr/bin/env python
# -*- coding: utf-8 -*-

# BET-64 Tool
# ..................................
# Copyright (c) 2018, Kendrick Walls
# ..................................
# Licensed under MIT (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ..........................................
# http://www.github.com/reactive-firewall/BET-64/LICENSE.md
# ..........................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


try:
	import os
	import re
	import sys
	import argparse
	import subprocess
	import base64
	import logging
	logging.basicConfig(
		level=logging.DEBUG,
		format=str("%(asctime)s [BET64] %(message)s"),
		datefmt=str("%a %b %d %H:%M:%S %Z %Y")
	)
except Exception as err:
	# Show Error Info
	print(str(type(err)))
	print(str(err))
	print(str(err.args))
	print(str(""))
	# Clean up Error
	err = None
	del(err)
	# Throw more relevant Error
	raise ImportError(str("Error Importing Python"))


__prog__ = str("""encode_b64""")
"""The name of this program is BET-64"""


__description__ = str(
	"""Encodes the content of a b64 file."""
)
"""Contains the description of the program."""


__epilog__ = str(
	"""Usually used to pack the file data into a b64 file."""
)
"""Contains the short epilog of the program CLI help text."""


__version__ = """1.0.0"""
"""The version of this program."""


START_HEADER = """-----START BASE64-----"""


STOP_FOOTER = """-----STOP  BASE64-----"""


# data_action = parser.add_mutually_exclusive_group()
# data_action.add_argument('--compress', default=False,
# action='store_true', help='compress the data')
# data_action.add_argument('--encrypt', action='store_false', help='encrypt the data')

# Lazy version 20160806


def parseArgs(arguments=None):
	"""Parses the CLI arguments. See argparse.ArgumentParser for more.
	param str - arguments - the array of arguments to parse.
		Usually sys.argv[1:]
	returns argparse.Namespace - the Namespace parsed with
		the key-value pairs.
	"""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description=__description__,
		epilog=__epilog__
	)
	parser.add_argument(
		'-i', '--in',
		dest='input_file',
		required=True,
		help='The normal file to read.'
	)
	parser.add_argument(
		'-o', '--out',
		dest='output_file',
		required=False,
		help='The output b64 file to write.'
	)
	safe_action = parser.add_mutually_exclusive_group()
	safe_action.add_argument(
		'-s', '--safe', default=True,
		action='store_true', dest='safe_mode',
		help='Always verify checksum before risking further action. Overrides --force'
	)
	safe_action.add_argument(
		'--force', action='store_false',
		dest='safe_mode',
		help='Always continue even if unable to verify checksum.' +
		'THIS IS VERY RISKY! Overrides --safe'
	)
	parser.add_argument(
		'-V', '--version',
		action='version', version=str(
			"%(prog)s {version}"
		).format(version=str(__version__))
	)
	# Lazy version 20160806
	return parser.parse_known_args(arguments)


def readFile(somefile):
	read_data = None
	theReadPath = str(somefile)
	with open(theReadPath, 'r') as f:
		read_data = f.read()
	f.close()
	return read_data


def writeFile(somefile, somedata):
	if somefile is None:
		return False
	elif somedata is None:
		return False
	theWritePath = str(somefile)
	try:
		with open(theWritePath, 'w') as f:
			f.write(somedata)
		f.close()
	except Exception:
		try:
			f.close()
		except BaseException:
			return False
		return False
	return True


def extractRegexPattern(theInput_Str, theInputPattern):
	"""
		Extracts the given regex patern.
		Param theInput_Str - a String to extract from.
		Param theInputPattern - the pattern to extract
		"""
	theList = None
	sourceStr = str(theInput_Str)
	match = re.compile(theInputPattern)
	theList = match.findall(sourceStr)
	return theList


def unwrapSpace(theInput_Str):
	sourceStr = str(theInput_Str)
	whitespace = re.compile("(\s)+")
	return whitespace.sub("", sourceStr)


def injectStartHeader():
	return str("\n{}\n").format(str(START_HEADER))


def injectb64Lines(theInputStr):
	b64databuff = unwrapSpace(theInputStr.encode('base64', 'strict'))
	someb64data = '\n'.join(b64databuff[pos:(pos + 64)] for pos in xrange(0, len(b64databuff), 64))
	return str('\n') + str(someb64data) + str('\n')


def injectStopFooter():
	return str("\n{}\n").format(str(STOP_FOOTER))


def calculateChecksum(theInputStr):
	import hashlib
	hash_object = hashlib.sha512(bytes(theInputStr))
	hex_dig = hash_object.hexdigest()
	return str(hex_dig)


def calculateEncodedChecksum(theInputStr):
	b64databuff = str(unwrapSpace(theInputStr.encode('base64', 'strict'))) + '\n'
	theb64Str = '\n'.join(b64databuff[pos:(pos + 64)] for pos in xrange(0, len(b64databuff), 64))
	return calculateChecksum(theb64Str)


def injectChecksum(theInputStr):
	b64databuff = calculateEncodedChecksum(theInputStr)
	chksum_str = '\n'.join(b64databuff[pos:(pos + 64)] for pos in xrange(0, len(b64databuff), 64))
	return str("\n{}").format(str(chksum_str))


def cleanTempFile():
	tmpName = str("/tmp/b64_content_") + str(os.getpid()) + str("_SWAP.data")
	subprocess.check_output(["rm", "-f", tmpName])
	return True


def renameTempFile(newFileName):
	if newFileName is None:
		return False
	tmpName = str("/tmp/b64_content_") + str(os.getpid()) + str("_SWAP.data")
	subprocess.check_output(["mv", "-f", tmpName, newFileName])
	return True


def rawFileB64(theInputStr):
	theResult = ""
	try:
		theResult = injectStartHeader()
		theResult = theResult + injectb64Lines(theInputStr)
		theResult = theResult + injectChecksum(theInputStr)
		theResult = theResult + injectStopFooter()
	except Exception:
		theResult = "an error occured while injecting the file's b64 content"
	return theResult


def main(argv=None):
	"""The Main Event."""
	try:
		args, extra = parseArgs(argv)
		input_file = args.input_file
		safe_mode = args.safe_mode
		output_file = args.output_file
		if (input_file is None) and (safe_mode is True):
			print "encode_b64: grumble....grumble: INPUT_FILE is set to None! Nothing to do."
			exit(3)
		elif (input_file is None):
			print("encode_b64: The --force won't help:")
			print("INPUT_FILE can not be set to None!")
			print("Nothing to do. write-in makes no sense ; b64 is for encoding files.")
			exit(4)
		if (output_file is None) and (safe_mode is True):
			print("encode_b64: grumble...WTF: OUTPUT_FILE is set to None! OUTPUT_MODE is b64.")
			print("This is silly! Nothing will be saved! try --force option.")
		elif (output_file is not None) and ('.b64' not in output_file) and (safe_mode is True):
			print("encode_b64: grumble...grumble: OUTPUT_FILE is set to invalid name!")
			print("MUST use '.b64' extension.")
		elif (output_file is not None) and ('.b64' not in output_file):
			print("encode_b64: whimper: OUTPUT_FILE is set to invalid name!")
			print("Should use '.b64' extension. This is silly!")
		elif (output_file is None) and (safe_mode is not True):
			print("encode_b64: The --force will help: OUTPUT_FILE will be guessed!")
			output_file = str(output_file) + str(".b64")

		if input_file is not None:
			theData = readFile(input_file)
			if output_file is not None:
				writeFile(str(output_file), rawFileB64(theData))
			elif output_file is None:
				print rawFileB64(theData)
		else:
			print "encode_b64: REALLY BAD ERROR: unknown state! ABORT!"
	except Exception:
		print("encode_b64: REALLY BAD ERROR: ACTION will not be completed! ABORT!")
		exit(5)
	exit(0)


if __name__ == '__main__':
	if (sys.argv is not None) and (sys.argv is not []):
		if (len(sys.argv) > 1):
			main(sys.argv[1:])
