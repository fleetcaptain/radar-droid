# Python script to automate 1) mapping an app's attack surface, at least some of it, and b) hunting through the decompiled apk for secrets like API keys
# Pre-alpha software... many values hardcoded and stuff. Not ready for general consumption
# by Carl Pearson <github.com/fleetcaptain> <bugcrowd.com/icewater>

# TODO - make script decompiler-agnostic. Currently only works with jadx output since we look for a ./resources/ folder in the app directory
# TODO - set the individual functions to return their findings via dicts, not just print in the function
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
debug = False





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
			print "[Provider] " +  str(item.attributes['android:name'].value)
			

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
			print "[Service] " + str(item.attributes['android:name'].value)


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
					#print item.attributes['android:name'].value + " " + permission
					actions = intent_filter.getElementsByTagName('action')

					# Get the broadcast strings that activate this receiver (should have values but let's check anyway...)
					if (actions != []):
						for action in actions:
							action_list.append(str(action.attributes['android:name'].value))
				
		# final verdict for this receiver
		if (is_exported):
			print "[Receiver] " + str(item.attributes['android:name'].value)
			print "\tPermission: " + permission
			for action in action_list:
				print '\tAction: ' + action
			print ''



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
						#print item.attributes['android:name'].value + " " + permission
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
			print "[Activity] " + item.attributes['android:name'].value + " " + str(is_exported) + " " + tag









# Start main code
parser = OptionParser('Usage: core.py -i <directory with decompiled app folders> -')
parser.add_option("-i", "--input", dest="input_dir", help="decompiled apk directory")
parser.add_option("-o", "--output", dest="out_file", help="Write results to specified output file")
parser.add_option("--debug", dest="debug", action="store_true", help="Enable verbose debug output")
parser.add_option("--secrets", dest="scan_secrets", action="store_true", help="Search for API keys, tokens, and other sensitive data")

(options, args) = parser.parse_args()
app_folder_directory = options.input_dir
out_file = options.out_file
debug = options.debug
scan_secrets = options.scan_secrets

#print 'Usage: core.py [directory with decompiled app folders] [debug true or false]'

# input - a folder path. Inside this folder should be app files decompiled with apktool
if (app_folder_directory == None):
	print 'You must specify an input directory'
	print parser.usage
	exit()

app_folders = [app_folder_directory]
# analyzing multiple APK folders at once is confusing
# Stick with the *nix principal of one tool, one purpose
# if users wish to analyze multiple folders, they can wrap this tool in a script
# at least, for now...
'''
for name in os.listdir(app_folder_directory):
            if os.path.isdir(os.path.join(app_folder_directory, name)):
		app_folders.append(app_folder_directory + name)
		if (debug):
			print "Added app " + name + " to analysis list"
'''
if (scan_secrets):
	# read in regex rules
	rule_file = open('./regex_rules.json', 'r')
	rules = json.loads(rule_file.read())
	for rule in rules:
		if (debug):
			print '[debug] Regex rule: ' + rule + " " + rules[rule]
		rules[rule] = re.compile(rules[rule])
	rule_file.close()

for app_folder in app_folders:
	path = app_folder + "/"

	# XML parsing of AndroidManifest.xml
	# check:
	# - backup (allowed, disallowed, not specified)
	# - exported activities
	# - activites with intent-filters
	# - exported providers
	# - exported services

	xmldoc = minidom.parse(path + 'AndroidManifest.xml')
	print '\n-------------------------------------'
	print '-- Results for ' + xmldoc.getElementsByTagName('manifest')[0].attributes['package'].value
	print ''#print '##############################'

	print '-- Misc Info --'
	# target SDK
	uses_sdk = xmldoc.getElementsByTagName('uses-sdk')
	target_api = 0
	try:
		target_api = int(uses_sdk[0].attributes['android:targetSdkVersion'].value)
	except:
		target_api = 'not specified'
	print "Target API: " + str(target_api)
	if (target_api < 17):
		print "Target API is old, check manifest manually for further vulnerabilities"

	# backup
	application = xmldoc.getElementsByTagName('application')
	try:
		backupvalue = str(application[0].attributes['android:allowBackup'].value)
	except Exception as e:
		# not set
		#print e
		backupvalue = "True (implicit)"
	print "Backup set: " + backupvalue

	# debuggable
	try:
		debuggable = str(application[0].attributes['debuggable'].value)
	except Exception as e:
		# not set
		debuggable = "False (implicit)"
	print "Debuggable: " + debuggable

	# permissions
	permissions = xmldoc.getElementsByTagName('uses-permission')
	for permission in permissions:
		p_name = str(permission.attributes['android:name'].value)
		if p_name in flagged_permissions:
			print "Uses: " + p_name

	# native libraries
	try:
		native_dirs = os.listdir(path + 'lib/')
	except:
		# does not use native dirs?
		continue
	if (debug):
		print '[debug] Subdirs of lib/: ' + str(native_dirs)
	if (len(native_dirs) > 0):
		print 'Uses native code'

	# All exported components that the manifest reveals
	# Note that some broadcast receivers and services can be created at runtime
	# TODO - pull out broadcast recievers and services from decompiled java code
	print '\n-- Exported Components --'

	# activities
	print ''
	getActivities(xmldoc)

	# providers
	print ''
	getProviders(xmldoc)

	# Services
	print ''
	getServices(xmldoc)

	# Static receivers
	print ''
	getReceivers(xmldoc)

	########################
	# REGEX
	#
	if (scan_secrets):
		#print '-- Results for ' + app_folder + ' --'
		print '\n-- Sensitive values --'

		for root, dirs, files in os.walk(path, topdown=False):
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
					#	print "[debug] Read file: " + filepath
					for key in rules:
						found_strings = rules[key].findall(filedata)
						if (found_strings):
							for found_string in found_strings:
								try:
									print 'Detected ' + key + ' in ' + name + ', value: ' + found_string
								except:
									# encode/decode error... just tell the user we found something
									print 'Detected ' + key + ' in ' + name + ', value: <encoding error>'
						
							
			
		print ''

print "\nDone"
