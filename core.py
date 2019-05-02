# Python script to automate 1) mapping an app's attack surface, at least some of it, and b) hunting through the decompiled apk for secrets like API keys
# Pre-alpha software... many values hardcoded and stuff. Not ready for general consumption
# by Carl Pearson <github.com/fleetcaptain> <bugcrowd.com/icewater>

# TODO - make script decompiler-agnostic. Currently only works with jadx output since we look for a ./resources/ folder in the app directory
# TODO - set the individual functions to return their findings via dicts, not just printString(in the function
# unknown if other decompilers make the same output structure

import sys, os, json, re
from subprocess import check_call,CalledProcessError      
from xml.dom import minidom
from os import listdir
from os.path import isfile, join
from optparse import OptionParser

rules = {}
activities = {}
blacklist = ['.jpg', '.png', '.gif', '.tiff']
flagged_permissions = ["android.permission.WRITE_EXTERNAL_STORAGE"]

#runtime_elements = ['onStartCommand(', 'handleMessage(', 'new WebView(', 'getExternalCacheDir()', 'getExternalFilesDir()', 'new BroadcastReceiver()', 'extends BroadcastReceiver', '@JavascriptInterface']
runtime_broadcast = ['sendBroadcast(']
debug = False
blacklist_receivers = []
structured_output = {} # the JSON output
silent = False



# consolidate printing stuff so we only need to check silent mode once
def printString(string):
	if (silent != True):
		print string


# given a path, walk through it and return the full path
# to all files
def getAllFiles(path):
	allfiles = []
	for root, dirs, files in os.walk(java, topdown=False):
		for name in files:
			filepath = os.path.join(root, name)
			allfiles.append(filepath)
	return allfiles


# parse xml document looking for exported or available content providers
def getProviders(xmldocument):
	items = xmldocument.getElementsByTagName("provider")
	# for each provider
	for item in items:
		is_exported = ''
		export_val = ''
		try:
			export_val = str(item.attributes['android:exported'].value)
		except:
			# not set
			export_val = "unknown"

		if (export_val == "true"):
			# exported
			is_exported = True
		else:
			is_exported = False
				
		# final verdict for this provider
		if (is_exported):
			printString("[Provider] " +  str(item.attributes['android:name'].value))
			tempd = {}
			tempd['id'] = item.attributes['android:name'].value
			structured_output['providers'].append(tempd)
			

# parse xml document looking for exported or available services
def getServices(xmldocument):
	items = xmldocument.getElementsByTagName("service")
	# for each service
	for item in items:
		is_exported = ''
		export_val = ''
		try:
			export_val = str(item.attributes['android:exported'].value)
		except:
			# not set
			export_val = "unknown"

		if (export_val == "true"):
			# exported
			is_exported = True
		else:
			is_exported = False
				
		# final verdict for this service
		if (is_exported):
			printString("[Service] " + str(item.attributes['android:name'].value))
			tempd = {}
			tempd['id'] = item.attributes['android:name'].value
			structured_output['services'].append(tempd)
			


# parse xml document looking for exported or available broadcast receivers
def getReceivers(xmldocument):
	items = xmldocument.getElementsByTagName("receiver")
	# for each receiver
	for item in items:
		is_exported = ''
		permission = ''
		action_list = []
		export_val = ''
		try:
			export_val = str(item.attributes['android:exported'].value)
		except:
			# not set
			export_val = "unknown"

		if (export_val == "false"):
			# explicitly not exported
			is_exported = False
		else:
			# true or not set
			intent_filters = item.getElementsByTagName('intent-filter')
			if (intent_filters != []):
				is_exported = True
				for intent_filter in intent_filters:
					#Check permission settings to see if we need a certain permission
					# to send broadcasts to this receiver
					permission = ""
					try:
						permission = str(item.attributes['android:permission'].value)
					except:
						# no permissions required?
						permission = "none"
					#printString(item.attributes['android:name'].value + " " + permission
					actions = intent_filter.getElementsByTagName('action')

					# Get the broadcast strings that activate this receiver (should have values but let's check anyway...)
					if (actions != []):
						for action in actions:
							action_list.append(str(action.attributes['android:name'].value))
				
		# final verdict for this receiver
		if (is_exported):
			printString("[Receiver] " + str(item.attributes['android:name'].value))
			printString("\tPermission: " + permission)
			tempd = {}
			tempd['id'] = item.attributes['android:name'].value
			tempd['permission'] = permission
			tempd['actions'] = []
			for action in action_list:
				printString('\tAction: ' + action)
				tempd['actions'].append(action)
			printString('')
			structured_output['receivers'].append(tempd)
		else:
			blacklist_receivers.append(str(item.attributes['android:name'].value))


# parse xml document looking for exported or available activities
def getActivities(xmldocument):
	items = xmldocument.getElementsByTagName("activity")
	# for each activity
	for item in items:
		is_exported = ''
		tag = ''
		export_val = ''
		try:
			export_val = str(item.attributes['android:exported'].value)
		except Exception as e:
			# not set - will check for intent-filters
			export_val = "unknown"

		if (export_val == "false"):
			# explicitly not exported
			is_exported = False
		else:
			# need to check if an intent filter is set.
			intent_filters = item.getElementsByTagName('intent-filter')
			if (intent_filters != []):
				is_exported = True
				for intent_filter in intent_filters:
					tag = "(intent-filter)"
					# exported due to intent filter (which may limit the exposed attack paths
					# Now check if it's a browsable activity. These can be reached via links like on webpages,	
					# so vulnerabilities might be easier to exploit
					categories = intent_filter.getElementsByTagName('category')
					if (categories != []):
						for category in categories:
							if (str(category.attributes['android:name'].value) == "android.intent.category.BROWSABLE"):
								tag = "(browsable)"
					'''
					elif (search_tag == "receiver"):
						permission = ""
						try:
							permission = item.attributes['android:permission'].value
						except:
							permission = " no permission?"
						#printString(item.attributes['android:name'].value + " " + permission
						# lets get some metadata about the receiver
						if (permission != " no permission?"):
							tag = "permission: " + item.attributes['android:permission'].value
						actions = intent_filter.getElementsByTagName('action')
						if (actions != []):
							for action in actions:
								tag = tag + "\n\t" + (str(action.attributes['android:name'].value)) + " "
					'''
			else:
				if (export_val == "true"): # if there are no intent filters but the activity was exported explicitly, we do want to report it
					is_exported = True
					tag = "(explicit)"
				
		# final verdict for this activity
		if (is_exported):
			printString("[Activity] " + item.attributes['android:name'].value + " " + str(is_exported) + " " + tag)
			tempd = {}
			tempd['id'] = item.attributes['android:name'].value
			tempd['method'] = tag
			structured_output['activities'].append(tempd)










# Start main code
parser = OptionParser('Usage: core.py -m <path to AndroidManifest.xml> -j <path to decompiled .java source code> -o (output file) --debug --secrets --high-confidence')
parser.add_option('-m', '--manifest', dest="manifest", help="AndroidManifest.xml file to analyze")
parser.add_option("-j", "--java", dest="java", help="directory with the app's decompiled .java source files")
parser.add_option("--high-confidence", action="store_true", dest="confidence", help="do not return low quality hits in source code search (ex: skip broadcasters in files with LocalBroadcastManager imported")
parser.add_option("-o", "--output", dest="out_file", help="Write results to specified output file")
parser.add_option("--debug", dest="debug", action="store_true", help="Enable verbose debug output")
parser.add_option("--json", dest="json", action="store_true", help="output results in JSON format for parsing by other scripts")
parser.add_option("--secrets", dest="scan_secrets", action="store_true", help="Search for API keys, tokens, and other sensitive data")

(options, args) = parser.parse_args()
out_file = options.out_file
debug = options.debug
scan_secrets = options.scan_secrets
java = options.java
confidence = options.confidence
manifest = options.manifest
usejson = options.json

check_all = True
#printString('Usage: core.py [directory with decompiled app folders] [debug true or false]'

# input - path to AndroidManifest.xml
if (manifest == None):
	printString('You must specify an input manifest file')
	printString(parser.usage)
	exit()

# analyzing multiple APK folders at once is confusing
# Stick with the *nix principal of one tool, one purpose
# if users wish to analyze multiple folders, they can wrap this tool in a script
# at least, for now...
'''
for name in os.listdir(app_folder_directory):
            if os.path.isdir(os.path.join(app_folder_directory, name)):
		app_folders.append(app_folder_directory + name)
		if (debug):
			printString("Added app " + name + " to analysis list"
'''

if (usejson):
	silent = True # no output anything but json

if (scan_secrets):
	# read in regex rules
	rule_file = open('./regex_rules.json', 'r')
	rules = json.loads(rule_file.read())
	for rule in rules:
		if (debug):
			printString('[debug] Regex rule: ' + rule + " " + rules[rule])
		rules[rule] = re.compile(rules[rule])
	rule_file.close()

if (confidence):
	check_all = False

# XML parsing of AndroidManifest.xml
# check:
# - backup (allowed, disallowed, not specified)
# - exported activities
# - activites with intent-filters
# - exported providers
# - exported services

xmldoc = minidom.parse(manifest)
packagename = xmldoc.getElementsByTagName('manifest')[0].attributes['package'].value
structured_output['app'] = packagename

printString('\n-------------------------------------')
printString('-- Results for ' + packagename)
printString('')#printString('##############################')

printString('-- Misc Info --')
# target SDK
uses_sdk = xmldoc.getElementsByTagName('uses-sdk')
target_api = 0
try:
	target_api = int(uses_sdk[0].attributes['android:targetSdkVersion'].value)
except:
	target_api = 'not specified'
structured_output['target_api'] = target_api
printString("Target API: " + str(target_api))
if (target_api < 17):
	printString("Target API is old, check manifest manually for further vulnerabilities")

# backup
application = xmldoc.getElementsByTagName('application')
try:
	backupvalue = str(application[0].attributes['android:allowBackup'].value)
except Exception as e:
	# not set
	#printString(e
	backupvalue = "True (implicit)"
structured_output['backup'] = backupvalue
printString("Backup set: " + backupvalue)

# debuggable
try:
	debuggable = str(application[0].attributes['debuggable'].value)
except Exception as e:
	# not set
	debuggable = "False (implicit)"
structured_output['debuggable'] = debuggable
printString("Debuggable: " + debuggable)

# permissions
permissions = xmldoc.getElementsByTagName('uses-permission')
structured_output['permissions'] = []
for permission in permissions:
	p_name = str(permission.attributes['android:name'].value)
	if p_name in flagged_permissions:
		printString("Uses: " + p_name)
		structured_output["permissions"].append(p_name)

# native libraries
'''
native_dirs = []
try:
	native_dirs = os.listdir(path + 'lib/')
except:
	# does not use native dirs?
	if (debug):
		printString("[debug] no native libraries"
if (debug):
	printString('[debug] Subdirs of lib/: ' + str(native_dirs)
if (len(native_dirs) > 0):
	printString('Uses native code'
'''

# All exported components that the manifest reveals
# Note that some broadcast receivers and services can be created at runtime
# TODO - pull out broadcast recievers and services from decompiled java code
printString('\n-- Exported Components --')

# activities
printString('')
structured_output['activities'] = []
getActivities(xmldoc)

# providers
printString('')
structured_output['providers'] = []
getProviders(xmldoc)

# Services
printString('')
structured_output['services'] = []
getServices(xmldoc)

# Static receivers
printString('')
structured_output['receivers'] = []
getReceivers(xmldoc)

structured_output['runtime_elements'] = {}
structured_output['runtime_elements']['webviews'] = []
structured_output['runtime_elements']['services'] = []
structured_output['runtime_elements']['receivers'] = []
structured_output['runtime_elements']['broadcasters'] = []

code_search = []
# Now let's hunt through decompiled code :)
if (java != None):
	file_list = getAllFiles(java)
	for fi in file_list:
		fi_name = fi.replace(java, '')
		f = open(fi, 'r')
		filedata = f.read()
		f.close()
		item_id = fi_name.replace('/', '.')
		'''
		for item in runtime_elements:
			if (item in filedata):
				code_search.append('Detected ' + item + ' in ' + fi_name)
			structured_output['item'] = fi_name
		'''
		if ('new WebView(' in filedata):
			#print 'here'
			if (check_all == False):
				#print 'check_all true'
				if (packagename in item_id):
					structured_output['runtime_elements']['webviews'].append(item_id)
			else:
				#print 'check_all false'
				structured_output['runtime_elements']['webviews'].append(item_id)

		elif ('onStartCommand(' in filedata or 'handleMessage(' in filedata):
			if (check_all == False):
				if (packagename in item_id):
					structured_output['runtime_elements']['services'].append(item_id)
			else:
				structured_output['runtime_elements']['services'].append(item_id)

		elif ('new BroadcastReceiver()' in filedata or 'extends BroadcastReceiver' in filedata):
			if (check_all == False):
				if (packagename in item_id):
					structured_output['runtime_elements']['receivers'].append(item_id)
			else:
				structured_output['runtime_elements']['receivers'].append(item_id)

		for item in runtime_broadcast:
			if (item in filedata and "LocalBroadcastManager" not in filedata):
				if (packagename in item_id):
					code_search.append('[High] Detected ' + item + ' in ' + item_id)
					structured_output['runtime_elements']['broadcasters'].append(item_id)
			else:
				if (check_all): # only return low confidence (i.e. probably local broadcast) items if user did not specify only high confidence items
					code_search.append('Detected ' + item + ' in ' + item_id)
					structured_output['runtime_elements']['broadcasters'].append(item_id)
code_search.sort()
for result in code_search:
	printString(result)
########################
# REGEX
#
if (scan_secrets):
	#printString('-- Results for ' + app_folder + ' --'
	printString('\n-- Sensitive values --')

	for root, dirs, files in os.walk(java, topdown=False):
		for name in files:
			skip = False
			filepath = os.path.join(root, name)
			for item in blacklist:
				if item in (filepath[-5:]):
					skip = True
			if (skip == False):
				#open file and run regex
				f = open(filepath, 'r')
				filedata = f.read()
				f.close()
				#if (debug):
				#	printString("[debug] Read file: " + filepath
				for key in rules:
					found_strings = rules[key].findall(filedata)
					if (found_strings):
						for found_string in found_strings:
							try:
								printString('Detected ' + key + ' in ' + name + ', value: ' + found_string)
							except:
								# encode/decode error... just tell the user we found something
								printString('Detected ' + key + ' in ' + name + ', value: <encoding error>')
					
						
		
	printString('')

printString("\nDone")

if (usejson):
	# actually print the json regardless of the silent mode
	print json.dumps(structured_output)
