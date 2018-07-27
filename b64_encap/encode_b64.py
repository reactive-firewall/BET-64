#! /usr/bin/env python

import argparse

START_HEADER = "-----START BASE64-----"
STOP_FOOTER  = "-----STOP  BASE64-----"

parser = argparse.ArgumentParser(prog='encode_b64', description='Decodes the content of a b64 file', epilog="Usually used to extract the file data from the a b64 file. Remember last option wins.")
parser.add_argument('-i', '--in', dest='input_file', required=True, help='The normal file to read')
parser.add_argument('-o', '--out', dest='output_file', required=False, help='The output b64 file to write.')
#data_action = parser.add_mutually_exclusive_group()
#data_action.add_argument('--compress', default=False, action='store_true', help='compress the data')
#data_action.add_argument('--encrypt', action='store_false', help='encrypt the data')
safe_action = parser.add_mutually_exclusive_group()
safe_action.add_argument('-s', '--safe', default=True, action='store_true', dest='safe_mode', help='Always verify checksum before risking further action. Overrides --force')
safe_action.add_argument('--force', action='store_false', dest='safe_mode', help='Always continue even if unable to verify checksum. THIS IS VERY RISKY! Overrides --safe')
parser.add_argument('-V', '--version', action='version', version='%(prog)s 6.0', help='NOT IMPLEMENTD, TL;DR versioning code implies that there is a version, as these tools have yet to transgress the sophomoric solutions of the novice, version shall be ignored')
# Lazy version 20160806

def readFile(somefile):
	import os
	read_data = None
	theReadPath = str(somefile)
	with open(theReadPath, 'r') as f:
		read_data = f.read()
	f.close()
	return read_data

def writeFile(somefile, somedata):
	import os
	if somefile is None:
		return False
	elif somedata is None:
		return False
	theWritePath = str(somefile)
	try:
		with open(theWritePath, 'w') as f:
			count = f.write(somedata)
		f.close()
	except:
		try:
			f.close()
		except:
			return False
		return False
	return True

def extractRegexPattern(theInput_Str, theInputPattern):
	import re
	sourceStr = str(theInput_Str)
	prog = re.compile(theInputPattern)
	theList = prog.findall(sourceStr)
	return theList

def unwrapSpace(theInput_Str):
	import re
	sourceStr = str(theInput_Str)
	whitespace = re.compile("(\s)+")
	return whitespace.sub("", sourceStr)

def injectStartHeader():
	return str('\n')+str(START_HEADER)+str('\n')

def injectb64Lines(theInputStr):
	someb64data_stream = unwrapSpace(theInputStr.encode('base64', 'strict'))
	someb64data = '\n'.join(someb64data_stream[pos:pos+64] for pos in xrange(0, len(someb64data_stream), 64))
	return str('\n')+str(someb64data)+str('\n')

def injectStopFooter():
	return str('\n')+str(STOP_FOOTER)+str('\n')

def calculateChecksum(theInputStr):
	import hashlib
	hash_object = hashlib.sha512( bytes(theInputStr) )
	hex_dig = hash_object.hexdigest()
	return str(hex_dig)

def calculateEncodedChecksum(theInputStr):
	someb64data_stream = str(unwrapSpace(theInputStr.encode('base64', 'strict')))+'\n'
	theb64Str = '\n'.join(someb64data_stream[pos:pos+64] for pos in xrange(0, len(someb64data_stream), 64))
	return calculateChecksum(theb64Str)

def injectChecksum(theInputStr):
	somechecksum_stream = calculateEncodedChecksum(theInputStr)
	somechecksum_data = '\n'.join(somechecksum_stream[pos:pos+64] for pos in xrange(0, len(somechecksum_stream), 64))
	return str('\n')+str(somechecksum_data)

def cleanTempFile():
	import base64
	import os
	import subprocess
	tmpName = str("/tmp/b64_content_")+str(os.getpid())+str("_SWAP.data")
	subprocess.check_output(["rm", "-f", tmpName])
	return True

def renameTempFile(newFileName):
	if newFileName is None:
		return False
	import base64
	import os
	import subprocess
	tmpName = str("/tmp/b64_content_")+str(os.getpid())+str("_SWAP.data")
	subprocess.check_output(["mv", "-f", tmpName, newFileName])
	return True

def rawFileB64(theInputStr):
	theResult = ""
	try:
		theResult = injectStartHeader()
		theResult = theResult + injectb64Lines(theInputStr)
		theResult = theResult + injectChecksum(theInputStr)
		theResult = theResult + injectStopFooter()
	except:
		theResult = "an error occured while injecting the file's b64 content"
	return theResult

try:
	args = parser.parse_args()
	input_file = args.input_file
	safe_mode = args.safe_mode
	output_file = args.output_file
	if (input_file is None) and (safe_mode is True):
		print "encode_b64: grumble....grumble: INPUT_FILE is set to None! Nothing to do."
		exit(3)
	elif (input_file is None):
		print "encode_b64: The --force won't help: INPUT_FILE can not be set to None! Nothing to do. write-in makes no sense ; b64 is for encoding files."
		exit(4)

	if (output_file is None) and (safe_mode is True):
		print "encode_b64: grumble...WTF: OUTPUT_FILE is set to None! OUTPUT_MODE is b64. This is silly! Nothing will be saved! try --force option."
	elif (output_file is not None) and ('.b64' not in output_file) and (safe_mode is True):
		print "encode_b64: grumble...grumble: OUTPUT_FILE is set to invalid name! MUST use '.b64' extension."
	elif (output_file is not None) and ('.b64' not in output_file):
		print "encode_b64: whimper: OUTPUT_FILE is set to invalid name! Should use '.b64' extension. This is silly!"
	elif (output_file is None) and (safe_mode is not True):
		print "encode_b64: The --force will help: OUTPUT_FILE will be guessed!"
		output_file = str(output_file)+str(".b64")

	if input_file is not None:
		theData = readFile(input_file)
		if output_file is not None:
			writeFile(str(output_file), rawFileB64(theData))
		elif output_file is None:
			print rawFileB64(theData)
	else:
		print "encode_b64: REALLY BAD ERROR: unknown state! ABORT!"

except:
	print "encode_b64: REALLY BAD ERROR: ACTION will not be completed! ABORT!"
	exit(5)

exit(0)
