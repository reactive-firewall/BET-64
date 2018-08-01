#! /usr/bin/env python

# default values
HEADER_START_STRING='-----START BASE64----'
HEADER_STOP_STRING='-----STOP  BASE64----'
MARKED_SPACER_STRING='V         :         |         :         |         :         |         :         |         :         |         :         |      V'

import argparse

parser = argparse.ArgumentParser(prog='check_b64', description='Checks the checksum of a b64 file', epilog="Usually used to determine the file integrity when decoding a b64")
parser.add_argument('-i', '--in', dest='input_file', required=True, help='the b64 file to type check')
group_action = parser.add_mutually_exclusive_group()
group_action.add_argument('-A', '--all', default=False, action='store_true', help='return all info, overrides other typing values')
group_action.add_argument('-a', '--action', default='all', choices=['all', 'sha512'], help='the typing action')

parser.add_argument('-d', '--decode-gpg-mode', dest='decode_gpg_mode', default=False, action='store_true', help='use GPG decoding if needed. Otherwise has no effect. EXPERIMENTAL.')
parser.add_argument('-V', '--version', action='version', version='%(prog)s 6.0', help='NOT IMPLEMENTD, TL;DR versioning code implies that there is a version, as these tools have yet to transgress the sophomoric solutions of the novice, version shall be ignored')
# Lazy version 20160806

def readFile(somefile, andDecodePGPifNeeded=False):
	import os
	read_data = None
	theReadPath = str(somefile)
	with open(theReadPath, 'r') as f:
		read_data = f.read()
	f.close()
	if (andDecodePGPifNeeded is True):
		if ('-----' in extractPGPBeginHeader(read_data)):
			read_data = None
			read_data = decodePGPFileAndRead(somefile)
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
			read_data = f.write(somedata)
		f.close()
	except Exception:
		try:
			f.close()
		except Exception:
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

def countb64Headers(theInputStr):
	theCount = len([x for x in extractStartHeader(theInputStr)])
	return theCount

def extractStartHeader(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<start_Header>(?:[-]{5}){1}(?:[S]{1}[T]{1}[A]{1}[R]{1}[T]{1}[\ ]{1}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})")

def extractChecksumLines(theInputStr):
	return extractRegexPattern(theInputStr, "(?:\s){1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[A]{1}[R]{1}[T]{1}[\ ]{1}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})(?:\s){1}(?:[\s\S]){1,}(?:\s){0,1}(?:\s){0,1}(?P<Checksum>(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}(?:[0-9a-zA-Z]{64}){1})+)(?:\s){0,1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})")[0]

def extractChecksum(theInputStr):
	return unwrapSpace(extractRegexPattern(theInputStr, "(?:\s){1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[A]{1}[R]{1}[T]{1}[\ ]{1}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})(?:\s){1}(?:[\s\S]){1,}(?:\s){0,1}(?:\s){0,1}(?P<Checksum>(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}(?:[0-9a-zA-Z]{64}){1})+)(?:\s){0,1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})")[0])

def extractb64Lines(theInputStr):
	return extractRegexPattern(theInputStr, "(?:\s){1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[A]{1}[R]{1}[T]{1}[\ ]{1}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})(?:\s)+(?P<base_64_chunks>(?:[\s\S])+)(?:\s){1}(?:\s){0,1}(?:(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}(?:[0-9a-zA-Z]{64}){1})+)(?:\s){0,1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})")[0]

def extractb64chunks(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<base_64_file>(?:\s){1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[A]{1}[R]{1}[T]{1}[\ ]{1}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})(?:\s)+(?:(?:[\s\S])+?)(?:\s){1}(?:\s){0,1}(?:(?:(?:[0-9a-zA-Z]{64}){1}(?:[\s]+){1}(?:[0-9a-zA-Z]{64}){1})+)(?:\s){0,1}(?:(?:[-]{5}){1}(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})(?:\s){1})")

def extractStopHeader(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<stop_header>(?:[-]{5}){1}(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})")

def extractPGPBeginHeader(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<begin_Header>(?:[-]{5}){1}(?:[B]{1}[E]{1}[G]{1}[I]{1}[N]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})")[0]

def extractPGPMessage(theInputStr):
	return extractRegexPattern(theInputStr, "(?:\s){0,1}(?:(?:[-]{5}){1}(?:[B]{1}[E]{1}[G]{1}[I]{1}[N]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})(?:\s){1}(?:(?:(?:[Vv]{1}[e]{1}[r]{1}[s]{1}[i]{1}[o]{1}[n]{1}[:]{1}(?:[\ \S]+){1}(?:[\s]{1}){1}(?:[Cc]{1}[o]{1}[m]{2}[e]{1}[n]{1}[t]{1}[:]{1}){1}(?:(?:[\ \S]+))(?:\s){0,1}){0,1}(?:[\s]+){1}(?P<base_64_chunks>(?:[\s\S])+)){1})(?:\s){0,1}(?:(?:[-]{5}){1}(?:[E]{1}[N]{1}[D]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})(?:\s+){0,1}")[0]

def extractPGPEndHeader(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<end_Header>(?:[-]{5}){1}(?:[E]{1}[N]{1}[D]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})")[0]

def decodePGPMessage(somefile, saveTmpFile=False):
	import os
	import subprocess
	tmpName=str("/tmp/pgp_content_")+str(os.getpid())+str("_SWAP.data")
	try:
		p1 = subprocess.Popen(["gpg2", "--use-agent", "-a", "-d", "--in", somefile], stdout=subprocess.PIPE)
		#p2 = subprocess.Popen(["tail", "-n", "+0"], stdin=p1.stdout, stdout=subprocess.PIPE)
		#p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
		theResult = p1.communicate()[0]
		p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
		writeFile(tmpName, theResult)
	except Exception:
		theResult = "an error occured while calculating expected file header"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult

def renameTempPGPFile(newFileName):
	if newFileName is None:
		return False
	import base64
	import os
	import subprocess
	tmpName = str("/tmp/pgp_content_")+str(os.getpid())+str("_SWAP.data")
	subprocess.check_output(["mv", "-f", tmpName, newFileName])
	return True


#DON'T USE UNLES YOU ARE TRYING TO KEEP THE FILE IN CLEAR Base 64 FORM
def decodePGPFile(somefile):
	decodePGPMessage(somefile, True)
	if ".b6" not in somefile[-5:-1]:
		if ".gp" in somefile[-5:-1]:
			thefile = somefile.replace(".gpg",".b64")
		else:
			thefile = somefile+".b64"
	else:
		thefile = somefile+".tmp"
	renameTempPGPFile(thefile)
	cleanTempPGPFile()
	return True

#this is kinda a hack that results in the file being read twice which is SLOW for large files
# on the flip side pre-optimization is the source of much headaches so we'll just clean up and use memory map later
def decodePGPFileAndRead(somefile):
	decodePGPMessage(somefile, True)
	if ".b6" not in somefile[-5:-1]:
		if ".gp" in somefile[-5:-1]:
			thefile = somefile.replace(".gpg",".b64")
		else:
			thefile = somefile+".b64"
	else:
		thefile = somefile+".tmp"
	renameTempPGPFile(thefile)
	cleanTempPGPFile()
	theResult = readFile(thefile)
	import os
	import subprocess
	subprocess.check_output(["rm", "-f", thefile])
	return theResult

def cleanTempPGPFile():
	import os
	import subprocess
	tmpPGPName=str("/tmp/pgp_content_")+str(os.getpid())+str("_SWAP.data")
	subprocess.check_output(["rm", "-f", tmpPGPName])
	return True

def calculateChecksum(theInputStr):
	import hashlib
	hash_object = hashlib.sha512( bytes(theInputStr) )
	hex_dig = hash_object.hexdigest()
	return str(hex_dig)

def calculateExpectedChecksum(theInputStr):
	theb64Str = str(extractb64Lines(theInputStr))
	return calculateChecksum(theb64Str)
	
args = parser.parse_args()
type_action = (args.action).lower()
if args.all is True:
	type_action = str('all')

if (type_action is None):
	print(str("check_b64: SYNTAX ERROR: ACTION can not be set to None!"))
	exit(3)

input_file = args.input_file

decode_mode = args.decode_gpg_mode

if type_action is not None:
	theData = readFile(input_file, decode_mode)
	fileChunkCount = countb64Headers(theData)
	if (fileChunkCount > 1):
		print(str("looks like input contains "+str(fileChunkCount)+" file chunks"))
	everyData = extractb64chunks(theData)
	for dataChunk in everyData:
		print(str(extractChecksum(dataChunk)))
		print(str(MARKED_SPACER_STRING))
		print(str("|         :         |         :         |         COMPARE WITH        :         |         :         |         :         |      |"))
		print(str(MARKED_SPACER_STRING))
		print(str(calculateExpectedChecksum(dataChunk)))
		if (fileChunkCount > 1):
			print(str("\n------------------------------------------------------------\n"))
exit(0)
