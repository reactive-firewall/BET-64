#! /usr/bin/env python

# TODO: add Header

import argparse
import os
import base64
import re
import subprocess
import hashlib

# TODO: add function for args

parser = argparse.ArgumentParser(prog='decode_b64', description='Decodes the content of a b64 file', epilog="Usually used to extract the file data from a b64 file. Remember last option wins.")
parser.add_argument('-i', '--in', dest='input_file', required=True, help='The b64 file to read')
parser.add_argument('-o', '--out', dest='output_file', required=False, help='The output file to write.')
data_action = parser.add_mutually_exclusive_group()
data_action.add_argument('--hex', default=False, action='store_true', dest='hex_mode', help='Output Hex Dump. Overrides --data')
data_action.add_argument('--data', action='store_false', dest='hex_mode', help='Output data. This is probably what you want. Overrides --hex')

chunk_action = parser.add_mutually_exclusive_group()
chunk_action.add_argument('--use-suffix', default=True, action='store_true', dest='use_suffix', help='Decode all chucks. will use sequential suffix. Overrides --use-suffix')
chunk_action.add_argument('--chunk-index', default=0, dest='chunk_index', required=False, help='Decode only chunk with the given index. This is probably not what you want. Overrides --all')
chunk_action.add_argument('--message', default=False, action='store_true', dest='message_mode', help='Output only non-base64 data. Overrides --use-suffix and --chunk-index. Only makes sense in combination with -d. EXPEREMENTAL.')

safe_action = parser.add_mutually_exclusive_group()
safe_action.add_argument('-s', '--safe', default=True, action='store_true', dest='safe_mode', help='Always verify checksum before risking further action. Implies --use-suffix. Overrides --force')
safe_action.add_argument('--force', action='store_false', dest='safe_mode', help='Always continue even if unable to verify checksum. THIS IS VERY RISKY! Overrides --safe')
parser.add_argument('-d', '--decode-gpg-mode', dest='decode_gpg_mode', default=False,  action='store_true', help='use GPG decoding if needed. Otherwise has no effect. REQUIRES GPG.')
parser.add_argument('-V', '--version', action='version', version='%(prog)s 6.1', help='NOT IMPLEMENTD, TL;DR versioning code implies that there is a version, as these tools have yet to transgress the sophomoric solutions of the novice, version shall be ignored')
# Lazy version 20160806

# TODO: improve read-write kludge into code

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
	except:
		try:
			f.close()
		except:
			return False
		return False
	return True

def extractRegexPattern(theInput_Str, theInputPattern):
	sourceStr = str(theInput_Str)
	prog = re.compile(theInputPattern)
	theList = prog.findall(sourceStr)
	return theList

def unwrapSpace(theInput_Str):
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

def extractMessage(theInputStr):
	temp_str = str(theInputStr)
	tempList = extractb64chunks(temp_str)
	theResult = temp_str
	for b64_chunk in tempList:
		theResult = theResult.replace(b64_chunk, "[BASE64 CHUNK]")
	return theResult

def extractStopHeader(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<stop_header>(?:[-]{5}){1}(?:[S]{1}[T]{1}[O]{1}[P]{1}[\ ]{2}[B]{1}[A]{1}[S]{1}[E]{1}[6]{1}[4]{1}){1}(?:[-]{5}){1})")

def extractPGPBeginHeader(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<begin_Header>(?:[-]{5}){1}(?:[B]{1}[E]{1}[G]{1}[I]{1}[N]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})")[0]

def extractPGPMessage(theInputStr):
	return extractRegexPattern(theInputStr, "(?:\s){0,1}(?:(?:[-]{5}){1}(?:[B]{1}[E]{1}[G]{1}[I]{1}[N]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})(?:\s){1}(?:(?:(?:[Vv]{1}[e]{1}[r]{1}[s]{1}[i]{1}[o]{1}[n]{1}[:]{1}(?:[\ \S]+){1}(?:[\s]{1}){1}(?:[Cc]{1}[o]{1}[m]{2}[e]{1}[n]{1}[t]{1}[:]{1}){1}(?:(?:[\ \S]+))(?:\s){0,1}){0,1}(?:[\s]+){1}(?P<base_64_chunks>(?:[\s\S])+)){1})(?:\s){0,1}(?:(?:[-]{5}){1}(?:[E]{1}[N]{1}[D]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})(?:\s+){0,1}")[0]

def extractPGPEndHeader(theInputStr):
	return extractRegexPattern(theInputStr, "(?P<end_Header>(?:[-]{5}){1}(?:[E]{1}[N]{1}[D]{1}[\ ]{1}[P]{1}[G]{1}[P]{1}[\ ]{1}[M]{1}[E]{1}[S]{2}[A]{1}[G]{1}[E]{1}){1}(?:[-]{5}){1})")[0]


#TODO: fix temp file name to use safe values

def decodePGPMessage(somefile, saveTmpFile=False):
	tmpName=str("/tmp/pgp_content_")+str(os.getpid())+str("_SWAP.data")
	try:
		p1 = subprocess.Popen(["gpg2", "--use-agent", "-a", "-d", "--in", somefile], stdout=subprocess.PIPE)
		#p2 = subprocess.Popen(["tail", "-n", "+0"], stdin=p1.stdout, stdout=subprocess.PIPE)
		#p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
		theResult = p1.communicate()[0]
		p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
		writeFile(tmpName, theResult)
	except:
		theResult = "an error occured while calculating expected file header"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult

def renameTempPGPFile(newFileName):
	if newFileName is None:
		return False
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
	subprocess.check_output(["rm", "-f", thefile])
	return theResult

def calculateChecksum(theInputStr):
	hash_object = hashlib.sha512( bytes(theInputStr) )
	hex_dig = hash_object.hexdigest()
	return str(hex_dig)

def calculateExpectedChecksum(theInputStr):
	theb64Str = str(extractb64Lines(theInputStr))
	return calculateChecksum(theb64Str)

def calculateExpectedFileType(theInputStr, saveTmpFile=False):
	tmpName=str("/tmp/b64_content_")+str(os.getpid())+str("_SWAP.data")
	if (os.path.isfile(tmpName) is not True):
		someb64data = base64.decodestring(extractb64Lines(theInputStr))
		if (writeFile(tmpName, someb64data) is not True):
			return None
	try:
		theResult=subprocess.check_output(["file", "-b", tmpName])
	except:
		theResult = "an error occured while calculating expected file type"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult

def calculateExpectedFileMime(theInputStr, saveTmpFile=False):
	tmpName=str("/tmp/b64_content_")+str(os.getpid())+str("_SWAP.data")
	if (os.path.isfile(tmpName) is not True):
		someb64data = base64.decodestring(extractb64Lines(theInputStr))
		if (writeFile(tmpName, someb64data) is not True):
			return None
	try:
		theResult=subprocess.check_output(["file", "-b", "--mime", tmpName])
	except:
		theResult = "an error occured while calculating expected file MIME"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	return theResult

def cleanTempPGPFile():
	tmpPGPName=str("/tmp/pgp_content_")+str(os.getpid())+str("_SWAP.data")
	subprocess.check_output(["rm", "-f", tmpPGPName])
	return True

def cleanTempFile():
	tmpName = str("/tmp/b64_content_")+str(os.getpid())+str("_SWAP.data")
	subprocess.check_output(["rm", "-f", tmpName])
	return True

def renameTempFile(newFileName):
	if newFileName is None:
		return False
	tmpName = str("/tmp/b64_content_")+str(os.getpid())+str("_SWAP.data")
	subprocess.check_output(["mv", "-f", tmpName, newFileName])
	return True

def printFileHex(theInputStr, saveTmpFile=False):
	tmpName = str("/tmp/b64_content_")+str(os.getpid())+str("_SWAP.data")
	if (os.path.isfile(tmpName) is not True):
		someb64data = base64.decodestring(extractb64Lines(theInputStr))
		if (writeFile(tmpName, someb64data) is not True):
			return None
	try:
		theResult = subprocess.check_output(["xxd", tmpName])
	except:
		theResult = "an error occured while extracting the file's hex content"
	if (saveTmpFile is not True):
		subprocess.check_output(["rm", "-f", tmpName])
	print theResult
	return True

def calculateAllFileMetadata(theInputStr):
	theResult = ""
	theStats = calculateExpectedFileStats(theInputStr, True)
	if theStats is not None:
		theResult = (theResult + theStats)
	fileKind = calculateExpectedFileType(theInputStr, True)
	if fileKind is not None:
		theResult = (theResult + fileKind)
	fileMime = calculateExpectedFileMime(theInputStr, True)
	if fileMime is not None:
		theResult = (theResult + fileMime)
	fileHeader = calculateExpectedFileHeader(theInputStr, False)
	if fileHeader is not None:
		theResult = (theResult + fileHeader)
	cleanTempFile()
	return theResult


#TODO create MAIN sections

args = parser.parse_args()
try:
	input_file = args.input_file
	safe_mode = args.safe_mode
	output_file = args.output_file
	hex_mode = args.hex_mode
	decode_mode = args.decode_gpg_mode
	message_mode = args.message_mode
	if message_mode and (safe_mode is not True):
		use_suffix = False
		chunk_index = 0
		print(str("decode_b64: grumble....grumble: MESSAGE MODE is TL;DR!"))
	else:
		chunk_index = args.chunk_index
		if chunk_index is not 0:
			use_suffix = False
		else:
			use_suffix = args.use_suffix

	if message_mode and (safe_mode is True):
		print(str("decode_b64: make me ... if you dare"))
		exit(3)

	if (input_file is None) and (safe_mode is True):
		print "decode_b64: grumble....grumble: INPUT_FILE is set to None! Nothing to do."
		exit(3)
	elif (input_file is None):
		print "decode_b64: The --force won't help: INPUT_FILE can not be set to None! Nothing to do."
		exit(4)

	if (output_file is None) and (safe_mode is True) and (hex_mode is False):
		print "decode_b64: grumble....grumble: OUTPUT_FILE is set to None! OUTPUT_MODE is data. This is unsafe! Nothing will be saved!"
	elif (hex_mode is True):
		print "decode_b64: HEX MODE: OUTPUT_FILE is set to None! Nothing will be saved."
	elif (output_file is None) and (safe_mode is not True):
		print "decode_b64: The --force will help: OUTPUT_FILE will be guessed!"
		output_file = str(output_file)+str(".guess")

	if input_file is not None:
		theData = readFile(input_file, decode_mode)
		fileChunkCount = countb64Headers(theData)
		everyData = [theData]
		if (fileChunkCount > 1):
			print(str("looks like input contains "+str(fileChunkCount)+" file chunks"))
			if (use_suffix is True):
				chunk_index = 0
			elif (chunk_index is not 0):
				everyData = [extractb64chunks(theData)[chunk_index]]
			elif (message_mode is True) and (decode_mode is True):
				print(extractMessage(theData))
				exit(0)
			else:
				everyData = extractb64chunks(theData)
		for dataChunk in everyData:
			if (fileChunkCount > 1):
				sufix=str("_"+str(chunk_index))
			if (extractChecksum(dataChunk) == calculateExpectedChecksum(dataChunk)) or (safe_mode is not True):
				if hex_mode is not True:
					fileMime = str(calculateExpectedFileMime(dataChunk, True)).lower()
					if '.' not in output_file[-5:-1]:
						if 'image' in fileMime:
							if 'tiff' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".tiff"))
							if 'png' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".png"))
							if 'jpeg' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".jpeg"))
							if 'gif' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".gif"))
							if 'photoshop' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".psd"))
						elif 'text' in fileMime:
							if 'html' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".html"))
							if 'plain' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".txt"))
							if 'rtf' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".rtf"))
							if 'x-shellscript' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".sh"))
							if 'x-java' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".java"))
							if 'x-python' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".py"))
							if 'x-php' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".php"))
							if 'x-c' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".code"))
						elif 'video' in fileMime:
							if 'mp4' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".mp4"))
							elif 'mpeg' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".mpeg"))
							elif 'mp3' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".mp3"))
							else:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".guess.video"))
						elif 'application' in fileMime:
							if 'msword' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str("_virus.doc"))
							elif 'bzip2' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".bz2"))
							elif 'gzip' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".gz"))
							elif 'zip' in fileMime:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".zip"))
							else:
								if output_file is not None:
									renameTempFile(str(output_file)+str(".data"))
						else:
							if output_file is not None:
								renameTempFile(str(output_file))
					else:
						if output_file is not None:
							renameTempFile(str(output_file))
					if output_file is None:
						printFileHex(dataChunk, False)
				else:
					printFileHex(dataChunk, False)
				cleanTempFile()
			else:
				print "decode_b64: CHECKSUM ERROR: ACTION will not be compleated! see --force"

except:
	print "decode_b64: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"
	exit(5)

exit(0)
