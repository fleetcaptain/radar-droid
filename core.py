# Python script to automate 1) mapping an app's attack surface, at least some of it, and b) hunting through the decompiled apk for secrets like API keys
# Pre-alpha software... many values hardcoded and stuff. Not ready for general consumption
# by Carl Pearson <github.com/fleetcaptain> <bugcrowd.com/icewater>

# TODO - make script decompiler-agnostic. Currently only works with jadx output since we look for a ./resources/ folder in the app directory
# TODO - set the individual functions to return their findings via dicts, not just printString(in the function
# unknown if other decompilers make the same output structure

import sys, os, json, re, sqlite3, time
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
packagename = None




## Database related methods
def initDB(db):
	db.execute('''CREATE TABLE activities (app text, activity text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE aliases (app text, alias text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE providers (app text, provider text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE receivers (app text, receiver text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE receiver_actions (app text, receiver text, action text)''')
	db.execute('''CREATE TABLE runtime_receivers (app text, receiver text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE services (app text, service text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE webviews (app text, webview text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE broadcasters (app text, broadcaster text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE servers (app text, item text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE jsbridges (app text, item text, tag text, first_seen text)''')	
	db.execute('''CREATE TABLE permissions (app text, permission text, tag text, first_seen text)''')
	db.execute('''CREATE TABLE appinfo (app text, sdk integer, backup text, debug text)''')
	db.commit()


# save general DB item
def saveItem(db, table, app, item, tag, first_seen):
	db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + item + "','" + tag + "','" + first_seen + "')")
	db.commit()


# save general app info
def saveAppInfo(db, app, sdk, backup, debug):
	db.execute("INSERT INTO appinfo VALUES ('" + app + "'," + str(sdk) + ",'" + backup + "','" + debug + "')")
	db.commit()


# save recevier actions
def saveAction(db, table, app, receiver, action):
	db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + receiver + "','" + action + "')")
	db.commit()



# consolidate printing stuff so we only need to check silent mode once
def printString(string):
	if (silent != True):
		print(string)


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
def getProviders(xmldocument, db):
	items = xmldocument.getElementsByTagName("provider")
	# for each provider
	for item in items:
		is_exported = ''
		export_val = ''
		permission_val = ''
		try:
			export_val = str(item.attributes['android:exported'].value)
		except:
			# not set
			export_val = "unknown"

		# If it has "Permission" set... I'm not interested in it
		# Note if writePermission or readPermission are set that is a limiting factor but we are still interested since would maybe interact with at least 1/2 of the read/write permission set
		# Unless write and read are both explicitly set, but we aren't checking that...
		try:
			permission_val = str(item.attributes['android:permission'].value)
		except:
			# not set
			permission_val = "unknown"

		if (export_val == "true" and permission_val == "unknown"):
			# exported
			is_exported = True
		else:
			is_exported = False
				
		# final verdict for this provider
		if (is_exported):
			printString("[Provider] " +  str(item.attributes['android:name'].value))
			saveItem(db, 'providers', packagename, item.attributes['android:name'].value, "exported", current_time)
			

# parse xml document looking for exported or available services
def getServices(xmldocument, db):
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
			saveItem(db, 'services', packagename, item.attributes['android:name'].value, "exported", current_time)
			


# parse xml document looking for exported or available broadcast receivers
def getReceivers(xmldocument, db):
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
			saveItem(db, 'receivers', packagename, str(item.attributes['android:name'].value), "intent-filter", current_time)
			for action in action_list:
					saveAction(db, 'receiver_actions', packagename, str(item.attributes['android:name'].value), action)
		else:
			blacklist_receivers.append(str(item.attributes['android:name'].value))


# parse xml document looking for exported or available activities
def getActivities(xmldocument, db):
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
				tag = "intent-filter"
				for intent_filter in intent_filters:
					# exported due to intent filter (which may limit the exposed attack paths
					# Now check if it's a browsable activity. These can be reached via links like on webpages,	
					# so vulnerabilities might be easier to exploit
					categories = intent_filter.getElementsByTagName('category')
					if (categories != []):
						for category in categories:
							if (str(category.attributes['android:name'].value) == "android.intent.category.BROWSABLE"):
								tag = "browsable"
								break
			else:
				if (export_val == "true"): # if there are no intent filters but the activity was exported explicitly, we do want to report it
					is_exported = True
					tag = "exported"
				
		# final verdict for this activity
		if (is_exported):
			printString("[Activity] " + item.attributes['android:name'].value + " " + str(is_exported) + " " + tag)
			saveItem(db, 'activities', packagename, item.attributes['android:name'].value, tag, current_time)



# parse xml document looking for exported or available activities
def getAliases(xmldocument, db):
	items = xmldocument.getElementsByTagName("activity-alias")
	# for each alias
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
				tag = "intent-filter"
				for intent_filter in intent_filters:
					# exported due to intent filter (which may limit the exposed attack paths
					# Now check if it's a browsable activity. These can be reached via links like on webpages,	
					# so vulnerabilities might be easier to exploit
					categories = intent_filter.getElementsByTagName('category')
					if (categories != []):
						for category in categories:
							if (str(category.attributes['android:name'].value) == "android.intent.category.BROWSABLE"):
								tag = "browsable"
								break
			else:
				if (export_val == "true"): # if there are no intent filters but the activity was exported explicitly, we do want to report it
					is_exported = True
					tag = "exported"
				
		# final verdict for this activity
		if (is_exported):
			printString("[Alias] " + item.attributes['android:name'].value + " " + str(is_exported) + " " + tag)
			saveItem(db, 'aliases', packagename, item.attributes['android:name'].value, tag, current_time)










# Start main code
parser = OptionParser('Usage: core.py -m <path to AndroidManifest.xml> -j <path to decompiled .java source code> -o (output file) --debug --secrets --high-confidence')
parser.add_option('-m', '--manifest', dest="manifest", help="AndroidManifest.xml file to analyze")
parser.add_option("-j", "--java", dest="java", help="directory with the app's decompiled .java source files")
parser.add_option("--high-confidence", action="store_true", dest="confidence", help="do not return low quality hits in source code search (ex: skip broadcasters in files with LocalBroadcastManager imported")
parser.add_option("-o", "--output", dest="out_file", help="Write results to specified output file")
parser.add_option("--debug", dest="debug", action="store_true", help="Enable verbose debug output")
parser.add_option("--secrets", dest="scan_secrets", help="JSON regex file containing search terms for API keys, tokens, and other sensitive data")

(options, args) = parser.parse_args()
out_file = options.out_file
debug = options.debug
scan_secrets = options.scan_secrets
java = options.java
confidence = options.confidence
manifest = options.manifest

current_time = str(time.time())

check_all = True

# input - path to AndroidManifest.xml
if (manifest == None):
	printString('You must specify an input manifest file')
	printString(parser.usage)
	exit()

if (scan_secrets != None):
	# read in regex rules
	rule_file = open(scan_secrets, 'r')
	rules = json.loads(rule_file.read())
	for rule in rules:
		if (debug):
			printString('[debug] Regex rule: ' + rule + " " + rules[rule])
		rules[rule] = re.compile(rules[rule])
	rule_file.close()

if (confidence):
	check_all = False

db_file = 'apps.db'
if (not os.path.exists(db_file)):
	# init tables if DB does not already exist
	conn = sqlite3.connect(db_file)
	initDB(conn)
	if (debug):
		printString("Created DB")
else:
	conn = sqlite3.connect(db_file)

# parse manifest
xmldoc = minidom.parse(manifest)
packagename = xmldoc.getElementsByTagName('manifest')[0].attributes['package'].value

printString('\n-------------------------------------')
printString('-- Results for ' + packagename)
printString('')#printString('##############################')

printString('-- Misc Info --')

uses_sdk = xmldoc.getElementsByTagName('uses-sdk')
target_api = 0
try:
	target_api = int(uses_sdk[0].attributes['android:targetSdkVersion'].value)
except:
	target_api = '-1'

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
	backupvalue = "true"
printString("Backup set: " + backupvalue)

# debuggable
try:
	debuggable = str(application[0].attributes['debuggable'].value)
except Exception as e:
	# not set
	debuggable = "false"
printString("Debuggable: " + debuggable)


saveAppInfo(conn, packagename, target_api, backupvalue, debuggable)

# permissions
permissions = xmldoc.getElementsByTagName('uses-permission')
structured_output['permissions'] = []
for permission in permissions:
	p_name = str(permission.attributes['android:name'].value)
	if p_name in flagged_permissions:
		printString("Uses: " + p_name)
		saveItem(conn, "permissions", packagename, p_name, "", current_time)


# All exported components that the manifest reveals
printString('\n-- Exported Components --')

# activities
printString('')
getActivities(xmldoc, conn)

# activity-alias
printString('')
getAliases(xmldoc, conn)

# providers
printString('')
getProviders(xmldoc, conn)

# Services
printString('')
getServices(xmldoc, conn)

# Static receivers
printString('')
getReceivers(xmldoc, conn)


code_search = []

# Now let's hunt through decompiled code :)
if (java != None):
	if (debug):
		printString("Analzying java source code at " + java)
	file_list = getAllFiles(java)
	for fi in file_list:
		fi_name = fi.replace(java, '')
		f = open(fi, 'r')
		filedata = f.read()
		f.close()
		item_id = fi_name.replace('/', '.')
		
		if (' WebView' in filedata):
			#print 'here'
			if (check_all == False):
				#print packagename
				#print item_id
				if (packagename in item_id):
					code_search.append('[High] Detected WebView in ' + item_id)
					saveItem(conn, 'webviews', packagename, item_id, "package-match", current_time)
			else:
				#print 'check_all false'
				code_search.append('Detected WebView in ' + item_id)
				saveItem(conn, 'webviews', packagename, item_id, "", current_time)

		if ('new BroadcastReceiver()' in filedata or 'extends BroadcastReceiver' in filedata):
			if (check_all == False):
				if (packagename in item_id):
					code_search.append('[High] Detected receiver in ' + item_id)
					saveItem(conn, 'runtime_receivers', packagename, item_id, "package-match", current_time)
			else:
				code_search.append('Detected receiver in ' + item_id)
				saveItem(conn, 'runtime_receivers', packagename, item_id, "", current_time)

		if ('@JavascriptInterface' in filedata):
			if (check_all == False):
				if (packagename in item_id):
					code_search.append('[High] Detected Javascript Bridge in ' + item_id)
					saveItem(conn, 'jsbridges', packagename, item_id, "package-match", current_time)
			else:
				code_search.append('Detected Javascript Bridge in ' + item_id)
				saveItem(conn, 'jsbridges', packagename, item_id, "", current_time)

		if ('new ServerSocket(' in filedata):
			if (check_all == False):
				if (packagename in item_id):
					code_search.append('[High] Detected ServerSocket in ' + item_id)
					saveItem(conn, 'servers', packagename, item_id, "package-match", current_time)
			else:
				code_search.append('Detected ServerSocket in ' + item_id)
				saveItem(conn, 'servers', packagename, item_id, "", current_time)



		for item in runtime_broadcast:
			if (item in filedata and "LocalBroadcastManager" not in filedata):
				if (packagename in item_id):
					code_search.append('[High] Detected ' + item + ' in ' + item_id)
					saveItem(conn, 'broadcasters', packagename, item_id, "package-match", current_time)
			else:
				if (check_all): # only return low confidence (i.e. probably local broadcast) items if user did not specify only high confidence items
					code_search.append('Detected ' + item + ' in ' + item_id)
					saveItem(conn, 'broadcasters', packagename, item_id, "", current_time)
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

conn.close()
printString("\nDone")
