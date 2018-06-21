# Python script to automate 1) mapping an app's attack surface, at least most of it, and b) hunting through the decompiled apk for secrets like API keys
# Pre-alpha software... many values hardcoded and stuff. Not ready for general consumption
# by Carl Pearson <github.com/fleetcaptain> <bugcrowd.com/icewater>

# TODO - implement optparse
# TODO - make script decompiler-agnostic. Currently only works with jadx output since we look for a ./resources/ folder in the app directory
# unknown if other decompilers make the same output structure

import sys, os, json, re, optparse
from subprocess import check_call,CalledProcessError      
from xml.dom import minidom
from os import listdir
from os.path import isfile, join

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
			# not set - check for intent-filters
			intent_filter = item.getElementsByTagName('intent-filter')
			if (intent_filter != []):
				is_exported = True
				tag = "(intent-filter)"
			else:
				is_exported = False
				tag = "(implicit)"
		names.append(item.attributes['android:name'].value)
		verdict.append(is_exported)
		tags.append(tag)
		#print item.attributes['android:name'].value + " " + str(is_exported) + " " + tag
	return names, verdict, tags









# Start main code

# sys.argv calls temporary, will convert to optparse at some point
try:
	debug = sys.argv[2]
except:
	pass

# input - a folder path. Inside this folder should be app files decompiled with jadx

app_folder_directory = sys.argv[1]
app_folders = []
for name in os.listdir(app_folder_directory):
            if os.path.isdir(os.path.join(a_dir, name)):
		app_folders.append(a_dir + name)
		if (debug):
			print "Added app " + name + " to analysis list"

for app_folder in app_folders:
	path = app_folder + "/"

	# XML parsing of AndroidManifest.xml
	# check:
	# - backup (allowed, disallowed, not specified)
	# - exported activities
	# - activites with intent-filters
	# - exported providers
	# - exported services

	xmldoc = minidom.parse(path + 'resources/AndroidManifest.xml')
	print '\n##############################'
	print '## Results for ' + xmldoc.getElementsByTagName('manifest')[0].attributes['package'].value
	print '##############################'

	print '\n-- Misc Info --'
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
	# read in regex rules
	rule_file = open('./regex_rules.json', 'r')
	rules = json.loads(rule_file.read())
	for rule in rules:
		#print rule + " " + rules[rule]
		rules[rule] = re.compile(rules[rule])
	rule_file.close()

	debug = True
	dev_debug = False
	
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
				if (dev_debug):
					print "Read file: " + filepath
				for key in rules:
					found_strings = rules[key].findall(filedata)
					if (found_strings):
						for found_string in found_strings:
							print 'Detected ' + key + ' in ' + name + ', value: ' + found_string
			
	print ''

print "\nDone"
