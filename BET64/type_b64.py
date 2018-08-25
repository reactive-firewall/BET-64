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
	import functools
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


__prog__ = str("""type_b64""")
"""The name of this program is BET-64"""


__description__ = str(
	"""Checks the type of a b64 file."""
)
"""Contains the description of the program."""


__epilog__ = str(
	""""Usually used to determine the file type for a file when decoding a b64"""
)
"""Contains the short epilog of the program CLI help text."""


__version__ = """1.0.0"""
"""The version of this program."""


def error_breakpoint(error, context=None):
	"""Just logs the error and returns None"""
	try:
		logger = logging.getLogger("""BET64""")
		logger.log(logging.WARNING, str("=" * 40))
		logger.log(logging.ERROR, str("An error occurred!"))
		logger.log(logging.INFO, str(context))
		logger.log(logging.INFO, str(type(error)))
		logger.log(logging.ERROR, str(error))
		logger.log(logging.INFO, str((error.args)))
	except Exception as err:
		print(str(err))
		err = None
		del err
	return None


def error_handling(func):
	"""Runs a function in try-except"""

	@functools.wraps(func)
	def safety_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			theOutput = error_breakpoint(error=err, context=func)
			err = None
			del err
		return theOutput

	return safety_func


@error_handling
def readFile(somefile, AndDecodePGPifNeeded=False):
	read_data = None
	theReadPath = str(somefile)
	with open(theReadPath, 'r') as f:
		read_data = f.read()
	f.close()
	if (AndDecodePGPifNeeded is True):
		if ("-----" in extractPGPBeginHeader(read_data)):
			read_data = None
			read_data = decodePGPFileAndRead(somefile)
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
		except Exception as err:
			error_breakpoint(error=err, context=writeFile)
			return False
		return False
	return True


@error_handling
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
	whitespace = re.compile("""(\s)+""")
	return whitespace.sub("", sourceStr)


@error_handling
def countb64Headers(theInputStr):
	theCount = len([x for x in extractStartHeader(theInputStr)])
	return theCount


def extractStartHeader(theInputStr):
	return extractRegexPattern(
		theInputStr,
		"""(?P<start_Header>(?:[-]{5}){1}""" +
		"""(?:(?:START){1}[\ ]{1}(?:BASE64){1}){1}""" +
		"""(?:[-]{5}){1})"""
	)


def extractChecksumLines(theInputStr):
	return extractRegexPattern(
		theInputStr,
		"""(?:\s){1}(?:(?:[-]{5}){1}""" +
		"""(?:[S]{1}[T]{1}[A]{1}[R]{1}[T]{1}[\ ]{1}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}""" +
		"""(?:[-]{5}){1})(?:\s){1}(?:[\s\S]){1,}(?:\s){0,1}(?:\s){0,1}""" +
		"""(?P<Checksum>(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}""" +
		"""(?:[0-9a-zA-Z]{64}){1})+)(?:\s){0,1}(?:(?:[-]{5}){1}""" +
		"""(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}""" +
		"""(?:[-]{5}){1})"""
	)[0]


def extractChecksum(theInputStr):
	return unwrapSpace(
		extractRegexPattern(
			theInputStr,
			"""(?:\s){1}(?:(?:[-]{5}){1}""" +
			"""(?:[S]{1}[T]{1}[A]{1}[R]{1}[T]{1}[\ ]{1}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}""" +
			"""(?:[-]{5}){1})(?:\s){1}(?:[\s\S]){1,}(?:\s){0,1}(?:\s){0,1}""" +
			"""(?P<Checksum>(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}(?:[0-9a-zA-Z]{64}){1})+)""" +
			"""(?:\s){0,1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}""" +
			"""[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})"""
		)[0]
	)


def extractb64Lines(theInputStr):
	return extractRegexPattern(
		theInputStr,
		"""(?:(?:(?:\s){1}""" +
		"""(?:(?:[-]{5}){1}(?:(?:START){1}[\ ]{1}(?:BASE64){1}){1}(?:[-]{5}){1})""" +
		"""(?:\s)+(?P<B64Lines>(?:[\s\S])+)?(?:\s){1}""" +
		"""(?:(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}(?:[0-9a-zA-Z]{64}){1})+)(?:\s){0,1}""" +
		"""(?:(?:[-]{5}){1}(?:(?:STOP){1}[\ ]{2}(?:BASE64){1}){1}(?:[-]{5}){1})(?:\s){1})+){1}"""
	)[0]


def extractb64chunks(theInputStr):
	"""
		returns the file chunks.
		see https://www.debuggex.com/r/a6274LS0b9t6CxEZ for reg ex
		"""
	theResult = []
	theResult = extractRegexPattern(
		theInputStr,
		"""(?:(?:(?:\s){1}""" +
		"""(?:(?:[-]{5}){1}(?:(?:START){1}[\ ]{1}(?:BASE64){1}){1}(?:[-]{5}){1})""" +
		"""(?:\s)+(?:(?:[\s\S])+)(?:\s){1}""" +
		"""(?:(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}(?:[0-9a-zA-Z]{64}){1})+)(?:\s){0,1}""" +
		"""(?:(?:[-]{5}){1}(?:(?:STOP){1}[\ ]{2}(?:BASE64){1}){1}(?:[-]{5}){1})(?:\s){1})+){1}"""
	)
	return theResult


def extractStopHeader(theInputStr):
	return extractRegexPattern(
		theInputStr,
		"""(?P<stop_header>(?:[-]{5}){1}""" +
		"""(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}""" +
		"""(?:[-]{5}){1})"""
	)


def extractPGPBeginHeader(theInputStr):
	return extractRegexPattern(
		theInputStr,
		"""(?P<begin_Header>(?:[-]{5}){1}""" +
		"""(?:[B]{1}[E]{1}[G]{1}[I]{1}[N]{1}""" +
		"""[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}""" +
		"""[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})"""
	)[0]


def extractPGPMessage(theInputStr):
	return extractRegexPattern(
		theInputStr,
		"""(?:\s){0,1}(?:(?:[-]{5}){1}""" +
		"""(?:[B]{1}[E]{1}[G]{1}[I]{1}[N]{1}""" +
		"""[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}""" +
		"""[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}""" +
		"""(?:[-]{5}){1})(?:\s){1}""" +
		"""(?:(?:(?:[Vv]{1}[e]{1}[r]{1}[s]{1}[i]{1}[o]{1}[n]{1}[:]{1}""" +
		"""(?:[\ \S]+){1}(?:[\s]{1}){1}(?:[Cc]{1}[o]{1}[m]{2}[e]{1}[n]{1}[t]{1}[:]{1}){1}""" +
		"""(?:(?:[\ \S]+))(?:\s){0,1}){0,1}(?:[\s]+){1}""" +
		"""(?P<base_64_chunks>(?:[\s\S])+)){1})(?:\s){0,1}(?:(?:[-]{5}){1}""" +
		"""(?:[E]{1}[N]{1}[D]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}""" +
		"""[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})(?:\s+){0,1}"""
	)[0]


def extractPGPEndHeader(theInputStr):
	return extractRegexPattern(
		theInputStr,
		"""(?P<end_Header>(?:[-]{5}){1}""" +
		"""(?:[E]{1}[N]{1}[D]{1}""" +
		"""[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}""" +
		"""[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})"""
	)[0]


@error_handling
def decodePGPMessage(somefile, saveTmpFile=False):
	tmpName = str("/tmp/pgp_content_") + str(os.getpid()) + str("_SWAP.data")
	try:
		p1 = subprocess.Popen(
			["gpg2", "--use-agent", "-a", "-d", "--in", somefile],
			stdout=subprocess.PIPE
		)
		# p2 = subprocess.Popen(["tail", "-n", "+0"], stdin=p1.stdout, stdout=subprocess.PIPE)
		# p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
		theResult = p1.communicate()[0]
		p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
		writeFile(tmpName, theResult)
	except Exception:
		theResult = "an error occured while calculating expected file header"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult


@error_handling
def renameTempPGPFile(newFileName):
	if newFileName is None:
		return False
	tmpName = str("/tmp/pgp_content_") + str(os.getpid()) + str("_SWAP.data")
	subprocess.check_output(["mv", "-f", tmpName, newFileName])
	return True


# DON'T USE UNLES YOU ARE TRYING TO KEEP THE FILE IN CLEAR Base 64 FORM
def decodePGPFile(somefile):
	decodePGPMessage(somefile, True)
	if ".b6" not in somefile[-5:-1]:
		if ".gp" in somefile[-5:-1]:
			thefile = somefile.replace(".gpg", ".b64")
		else:
			thefile = somefile + ".b64"
	else:
		thefile = somefile + ".tmp"
	renameTempPGPFile(thefile)
	cleanTempPGPFile()
	return True


# this is kinda a hack that results in the file being read twice which is SLOW for large files
# on the flip side pre-optimization is the source of much headaches
# so we'll just clean up and use memory map later
@error_handling
def decodePGPFileAndRead(somefile):
	decodePGPMessage(somefile, True)
	if str(".b6") not in somefile[-5:]:
		if str(".gp") in somefile[-5:]:
			thefile = somefile.replace(".gpg", ".b64")
		else:
			thefile = somefile + ".b64"
	else:
		thefile = somefile + ".tmp"
	renameTempPGPFile(thefile)
	cleanTempPGPFile()
	theResult = readFile(thefile)
	subprocess.check_output(["rm", "-f", thefile])
	return theResult


@error_handling
def calculateChecksum(theInputStr):
	import hashlib
	hash_object = hashlib.sha512(bytes(theInputStr))
	hex_dig = hash_object.hexdigest()
	return str(hex_dig)


@error_handling
def calculateExpectedChecksum(theInputStr):
	theb64Str = str(extractb64Lines(theInputStr))
	return calculateChecksum(theb64Str)


@error_handling
def calculateExpectedFileType(theInputStr, saveTmpFile=False):
	import base64
	tmpName = str("/tmp/b64_content_") + str(os.getpid()) + str("_SWAP.data")
	if (os.path.isfile(tmpName) is not True):
		someb64data = base64.decodestring(extractb64Lines(theInputStr))
		if (writeFile(tmpName, someb64data) is not True):
			return None
	try:
		theResult = subprocess.check_output(["file", "-b", tmpName])
	except Exception:
		theResult = "an error occured while calculating expected file type"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult


@error_handling
def calculateExpectedFileMime(theInputStr, saveTmpFile=False):
	import base64
	tmpName = str("/tmp/b64_content_") + str(os.getpid()) + str("_SWAP.data")
	if (os.path.isfile(tmpName) is not True):
		someb64data = base64.decodestring(extractb64Lines(theInputStr))
		if (writeFile(tmpName, someb64data) is not True):
			return None
	try:
		theResult = subprocess.check_output(["file", "-b", "--mime", tmpName])
	except Exception:
		theResult = "an error occured while calculating expected file MIME"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult


@error_handling
def cleanTempPGPFile():
	tmpPGPName = str("/tmp/pgp_content_") + str(os.getpid()) + str("_SWAP.data")
	subprocess.check_output(["rm", "-f", tmpPGPName])
	return True


@error_handling
def cleanTempFile():
	tmpName = str("/tmp/b64_content_") + str(os.getpid()) + str("_SWAP.data")
	subprocess.check_output(["rm", "-f", tmpName])
	return True


@error_handling
def calculateExpectedFileStats(theInputStr, saveTmpFile=False):
	import base64
	tmpName = str("/tmp/b64_content_") + str(os.getpid()) + str("_SWAP.data")
	if (os.path.isfile(tmpName) is not True):
		someb64data = base64.decodestring(extractb64Lines(theInputStr))
		if (writeFile(tmpName, someb64data) is not True):
			return None
	try:
		theResult = subprocess.check_output(["stat", tmpName])
	except Exception:
		theResult = "an error occured while calculating expected file stats"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult


@error_handling
def calculateExpectedFileHeader(theInputStr, saveTmpFile=False):
	import base64
	tmpName = str("/tmp/b64_content_") + str(os.getpid()) + str("_SWAP.data")
	if (os.path.isfile(tmpName) is not True):
		someb64data = base64.decodestring(extractb64Lines(theInputStr))
		if (writeFile(tmpName, someb64data) is not True):
			return None
	try:
		p1 = subprocess.Popen(["xxd", tmpName], stdout=subprocess.PIPE)
		p2 = subprocess.Popen(["head", "-n", "1"], stdin=p1.stdout, stdout=subprocess.PIPE)
		p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
		theResult = p2.communicate()[0]
	except Exception:
		theResult = "an error occured while calculating expected file header"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult


@error_handling
def calculateAllFileMetadata(theInputStr, saveTmpFile=True):
	theResult = ""
	theStats = calculateExpectedFileStats(theInputStr, saveTmpFile)
	if theStats is not None:
		theResult = (theResult + theStats)
	fileKind = calculateExpectedFileType(theInputStr, saveTmpFile)
	if fileKind is not None:
		theResult = (theResult + fileKind)
	fileMime = calculateExpectedFileMime(theInputStr, saveTmpFile)
	if fileMime is not None:
		theResult = (theResult + fileMime)
	fileHeader = calculateExpectedFileHeader(theInputStr, False)
	if fileHeader is not None:
		theResult = (theResult + fileHeader)
	cleanTempFile()
	return theResult


MODE_OPTIONS = dict({
	'all': calculateAllFileMetadata,
	'header': calculateExpectedFileHeader,
	'magic': calculateExpectedFileType,
	'mime': calculateExpectedFileMime,
	'stats': calculateExpectedFileStats
})
"""The callable function tasks of this program."""


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
		help='The b64 file to type check'
	)
	group_action = parser.add_mutually_exclusive_group(required=True)
	group_action.add_argument(
		'-A', '--all',
		default=False, action='store_true',
		help='Return all info, overrides other typing values. Same as -a=all'
	)
	group_action.add_argument(
		'-a', '--action', default='all',
		choices=MODE_OPTIONS.keys(),
		help='the help text for this option.'
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
		'-d', '--decode-gpg-mode',
		dest='decode_gpg_mode',
		default=False,
		action='store_true',
		help='use GPG decoding if needed. Otherwise has no effect. REQUIRES GPG.'
	)
	parser.add_argument(
		'-V', '--version',
		action='version', version=str(
			"%(prog)s {version}"
		).format(version=str(__version__))
	)
	# Lazy version 20160806
	return parser.parse_known_args(arguments)


def printError(errMessge):
	logger = logging.getLogger(str('BET64'))
	return logger.log(logging.ERROR, str("type_b64: {}").format(str(errMessge)))


def main(argv=None):
	"""The Main Event."""
	try:
		args, extra = parseArgs(argv)
		type_action = (args.action).lower()
		cacheTmpFiles = False
		if args.all is True:
			type_action = str('all')
			cacheTmpFiles = True
		if (type_action is None):
			printError("SYNTAX ERROR: ACTION can not be set to None!")
			exit(3)
		input_file = args.input_file
		safe_mode = args.safe_mode
		decode_mode = args.decode_gpg_mode
		if type_action is not None:
			theData = readFile(input_file, decode_mode)
			fileChunkCount = countb64Headers(theData)
			if (fileChunkCount > 1):
				print(str("looks like input contains " + str(fileChunkCount) + " file chunks"))
			everyData = extractb64chunks(theData)
			for dataChunk in everyData:
				actual = extractChecksum(dataChunk)
				expect = calculateExpectedChecksum(dataChunk)
				if (str(actual) in str(expect)) or (safe_mode is not True):
					if type_action in MODE_OPTIONS.keys():
						print(MODE_OPTIONS[type_action](dataChunk, cacheTmpFiles))
					else:
						raise RuntimeError("Checksum passed but action not posible")
				else:
					printError("CHECKSUM ERROR: ACTION will not be compleated! see --force")
				if (fileChunkCount > 1):
					print(str("\n------------------------------------------------------------\n"))
	except Exception as err:
		printError(str(err))
		printError(
			str(
				"CRITICAL - An error occured while handling " +
				"the cascading failure."
			)
		)
		exit(3)
	exit(0)


if __name__ == '__main__':
	if (sys.argv is not None) and (sys.argv is not []):
		if (len(sys.argv) > 1):
			main(sys.argv[1:])

