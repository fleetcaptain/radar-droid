# Python script to automate 1) mapping an app's attack surface, at least most of it, and b) hunting through the decompiled apk for secrets like API keys
# Pre-alpha software... many values hardcoded and stuff. Not ready for general consumption
# by Carl Pearson <github.com/fleetcaptain> <bugcrowd.com/icewater>

# TODO - implement optparse
# TODO - make script decompiler-agnostic. Currently only works with jadx output since we look for a ./resources/ folder in the app directory
# unknown if other decompilers make the same output structure

import sys, os, json, re
from subprocess import check_call,CalledProcessError      
from xml.dom import minidom
from os import listdir
from os.path import isfile, join
from optparse import OptionParser

rules = {}
blacklist = ['.jpg', '.png', '.gif', '.tiff']
flagged_permissions = ["android.permission.WRITE_EXTERNAL_STORAGE"]
debug = False

# find all exported instances of search_tag. Includes intent-filters
def auditElement(xmldocument, search_tag):
	verdict = []
	names = []
	tags = []
	items = xmldocument.getElementsByTagName(search_tag)
	for item in items:
		is_exported = ''
		tag = ''
		try:
			if (str(item.attributes['android:exported'].value) == "true"):
				is_exported = True
			else:
				is_exported = False
		except Exception as e:
			# not set - will check for intent-filters
			x = 0
		finally:
			# check intent_filters anyway, this will overwride the tag if browsable set
			# which we'd like to know, even if the activity already explicitly exported
			intent_filters = item.getElementsByTagName('intent-filter')
			if (intent_filters != []):
				is_exported = True
				tag = "(intent-filter)" # override this later if BROWSABLE set
				for intent_filter in intent_filters:
					categories = intent_filter.getElementsByTagName('category')
					if (categories != []):
						for category in categories:
							if (str(category.attributes['android:name'].value) == "android.intent.category.BROWSABLE"):
								tag = "(browsable)"
			else:
				if (is_exported == True): # don't override if it was already set to true by explicitly exported activity
					is_exported = False
					tag = "(implicit)"
		names.append(item.attributes['android:name'].value)
		verdict.append(is_exported)
		tags.append(tag)
		#print item.attributes['android:name'].value + " " + str(is_exported) + " " + tag
	return names, verdict, tags









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
		target_api = '-1'
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
	# returns name, exported, and tag
	names, verdicts, tags = auditElement(xmldoc, 'activity')
	for x in range(0, len(names)):
		if (verdicts[x] == True):
			print "[Activity] " + names[x] + " " + tags[x]

	# providers
	print ''
	names, verdicts, tags = auditElement(xmldoc, 'provider')
	for x in range(0, len(names)):
		if (verdicts[x] == True):
			print "[Provider] " + names[x] + " " + tags[x]
	# Services
	print ''
	names, verdicts, tags = auditElement(xmldoc, 'service')
	for x in range(0, len(names)):
		if (verdicts[x] == True):
			print "[Service] " + names[x] + " " + tags[x]

	# Static receivers
	print ''
	names, verdicts, tags = auditElement(xmldoc, 'receiver')
	for x in range(0, len(names)):
		if (verdicts[x] == True):
			print "[Receiver] " + names[x] + " " + tags[x]


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
