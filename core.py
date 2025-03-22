# Python script to automate 1) mapping an app's attack surface, at least some of it, and b) hunting through the decompiled apk for secrets like API keys
# by Carl Pearson <github.com/fleetcaptain> <bugcrowd.com/icewater>

import sys, os, json, re, sqlite3, time
from subprocess import check_call,CalledProcessError      
from xml.dom import minidom
from os import listdir
from os.path import isfile, join
from optparse import OptionParser

rules = {}
activities = {}
blacklist = ['.jpg', '.png', '.gif', '.tiff', '.webp', '.dex', '.matc', '.kotlin_module']
flagged_permissions = ["android.permission.WRITE_EXTERNAL_STORAGE"]
seen_authorities = []

#runtime_elements = ['onStartCommand(', 'handleMessage(', 'new WebView(', 'getExternalCacheDir()', 'getExternalFilesDir()', 'new BroadcastReceiver()', 'extends BroadcastReceiver', '@JavascriptInterface']
runtime_broadcast = ['sendBroadcast(']
debug = False
blacklist_receivers = []
structured_output = {} # the JSON output
silent = False
packagename = None


    

## Database related methods
def initDB(db):
    db.execute('''CREATE TABLE activities (app text, activity text, tag text, input text, permission text, first_seen text)''')
    db.execute('''CREATE TABLE aliases (app text, alias text, target text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE providers (app text, provider text, permission_read text, permission_write text, protection text, permission text, first_seen text)''')
    db.execute('''CREATE TABLE receivers (app text, receiver text, permission text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE receiver_actions (app text, receiver text, action text)''')
    db.execute('''CREATE TABLE runtime_receivers (app text, receiver text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE services (app text, service text, permission text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE webviews (app text, webview text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE broadcasters (app text, broadcaster text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE servers (app text, item text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE loopback (app text, item text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE jsbridges (app text, item text, tag text, first_seen text)''')    
    db.execute('''CREATE TABLE jsconsoles (app text, item text, tag text, first_seen text)''')    
    db.execute('''CREATE TABLE uses_permissions (app text, permission text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE defines_permissions (app text, permission text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE appinfo (app text, sdk integer, backup text, debug text)''')
    db.execute('''CREATE TABLE firebase_manifest (app text, url text, app_id text, project_id, gapikey text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE activity_actions (app text, component text, action text, tag text, first_seen text)''')
    db.execute('''CREATE TABLE service_actions (app text, component text, action text, tag text, first_seen text)''')
    db.commit()



# save action item
def saveActivityAction(db, table, app, component, action, tag, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + component + "','" + action + "','" + tag + "','" + first_seen + "')")
    db.commit()
    
# save action item
def saveServiceAction(db, table, app, component, action, tag, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + component + "','" + action + "','" + tag + "','" + first_seen + "')")
    db.commit()
        
# save Activity item
def saveActivity(db, table, app, item, tag, input_tag, permission, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + item + "','" + tag + "','" + input_tag + "','" + permission + "','" + first_seen + "')")
    db.commit()

# save Firebase
def saveFirebaseManifest(db, table, app, url, app_id, project_id, gapikey, tag, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + url + "','" + app_id  + "','"  + project_id + "','" + gapikey + "','" + tag + "','" + first_seen + "')")
    db.commit()

# save general DB item
def saveItem(db, table, app, item, tag, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + item + "','" + tag + "','" + first_seen + "')")
    db.commit()

def saveItemWithPermission(db, table, app, item, permission, tag, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + item + "','" + permission + "','" + tag + "','" + first_seen + "')")
    db.commit()

# save general DB item
def saveAlias(db, table, app, item, target, tag, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + item + "','" + target + "','" + tag + "','" + first_seen + "')")
    db.commit()

# save general app info
def saveAppInfo(db, app, sdk, backup, debug):
    db.execute("INSERT INTO appinfo VALUES ('" + app + "'," + str(sdk) + ",'" + backup + "','" + debug + "')")
    db.commit()

# save recevier actions
def saveReceiverAction(db, table, app, receiver, action):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + receiver + "','" + action + "')")
    db.commit()

def saveProvider(db, table, app, item, permission_read, permission_write, protection, permission, first_seen):
    db.execute("INSERT INTO " + table + " VALUES ('" + app + "','" + item + "','" + permission_read + "','" + permission_write + "','" + protection + "','" + permission + "','" + first_seen + "')")
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
        permission_read = ''
        permission_write = ''
        
        name = None
        try:
            name = str(item.attributes['android:name'].value)
        except:
            name = 'error'
        
        # start by collecting the authority for later analysis
        authority = ''
        try:
            authority = str(item.attributes['android:authorities'].value)
            seen_authorities.append(authority)
        except:
            authority = ''
            
        try:
            export_val = str(item.attributes['android:exported'].value)
        except:
            # not set
            export_val = "unknown"

        # If it has "Permission" set... I'm not interested in it
        try:
            permission_val = str(item.attributes['android:permission'].value)
        except:
            # not set
            permission_val = "N/A"

        # check write permission
        try:
            permission_write = str(item.attributes['android:writePermission'].value)
        except:
            permission_write = 'N/A'

        # check read permission
        try:
            permission_read = str(item.attributes['android:readPermission'].value)
        except:
            permission_read = 'N/A'

        # check protection
        try:
            protection = str(item.attributes['android:protectionLevel'].value)
            #permission_val = 'protectionLevel'
        except:
            protection = 'N/A'
            
        if (export_val == "true"):
            # exported
            is_exported = True
        else:
            is_exported = False
                
        # final verdict for this provider
        if (is_exported):
            printString("[Provider] " +  name)
            if (permission_read != ''):
                printString("\tread permission: " + permission_read)
            if (permission_write != ''):
                printString('\twrite permission: ' + permission_write)
            if (permission_val != 'N/A'):
                printString('\tpermission: ' + permission_val)
            if (protection != 'N/A'):
                printString('\tprotection:  ' + protection)
            saveProvider(db, 'providers', packagename, name, str(permission_read), str(permission_write), str(protection), str(permission_val), current_time)
            

# parse xml document looking for exported or available services
def getServices(xmldocument, db):
    items = xmldocument.getElementsByTagName("service")
    # for each service
    for item in items:
        is_exported = ''
        export_val = ''
        actions = []
        try:
            export_val = str(item.attributes['android:exported'].value)
        except:
            # not set
            export_val = "unknown"

        try:
            enabled_val = str(item.attributes['android:enabled'].value)
        except Exception as e:
            # not set - assume enabled
            enabled_val = "true"
            
        if (export_val == "true" and enabled_val == "true"):
            # exported
            is_exported = True
        else:
            is_exported = False # use this variable to track both exported False and enabled False states
        
        # check for permissions
        permission = ""
        try:
            permission = str(item.attributes['android:permission'].value)
        except:
            # no permissions required?
            permission = "N/A"
        # final verdict for this service
        if (is_exported):
            intent_filters = item.getElementsByTagName('intent-filter')
            if (intent_filters != []):
                for intent_filter in intent_filters:
                    # now check for actions and record those. This helps us do analysis later to know what the item might be expecting
                    action_elements = intent_filter.getElementsByTagName('action')
                    if (action_elements != []):
                        for action_element in action_elements:
                            actions.append(str(action_element.attributes['android:name'].value))
                            
            printString("[Service] " + str(item.attributes['android:name'].value))
            printString("\tPermission: " + permission)
            saveItemWithPermission(db, 'services', packagename, item.attributes['android:name'].value, permission, "exported", current_time)
            for action in actions:
                saveServiceAction(db, 'service_actions', packagename, item.attributes['android:name'].value, action, "", current_time)        


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
                #Check permission settings to see if we need a certain permission
                # to send broadcasts to this receiver
                permission = ""
                try:
                    permission = str(item.attributes['android:permission'].value)
                except:
                    # no permissions required?
                    permission = "N/A"
                #printString(item.attributes['android:name'].value + " " + permission
                for intent_filter in intent_filters:
                    actions = intent_filter.getElementsByTagName('action')

                    # Get the broadcast strings that activate this receiver (should have values but let's check anyway...)
                    if (actions != []):
                        for action in actions:
                            action_list.append(str(action.attributes['android:name'].value))
                
        # final verdict for this receiver
        if (is_exported):
            printString("[Receiver] " + str(item.attributes['android:name'].value))
            printString("\tPermission: " + permission)
            saveItemWithPermission(db, 'receivers', packagename, str(item.attributes['android:name'].value), permission, "intent-filter", current_time)
            for action in action_list:
                    saveReceiverAction(db, 'receiver_actions', packagename, str(item.attributes['android:name'].value), action)
        else:
            blacklist_receivers.append(str(item.attributes['android:name'].value))


# parse xml document looking for exported or available activities
def getActivities(xmldocument, db, coderoot):
    items = xmldocument.getElementsByTagName("activity")
    # for each activity
    for item in items:
        is_exported = ''
        tag = ''
        export_val = ''
        enabled_val = ''
        actions = []
        
        try:
            export_val = str(item.attributes['android:exported'].value)
        except Exception as e:
            # not set - will check for intent-filters
            export_val = "unknown"

        try:
            enabled_val = str(item.attributes['android:enabled'].value)
        except Exception as e:
            # not set - assume enabled
            enabled_val = "true"
            
            
        if (export_val == "false" or enabled_val == "false"):
            # explicitly not exported
            is_exported = False # use this variable to track both exported False and enabled False states
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
                    # now check for actions and record those. This helps us do analysis later to know what the item might be expecting
                    action_elements = intent_filter.getElementsByTagName('action')
                    if (action_elements != []):
                        for action_element in action_elements:
                            actions.append(str(action_element.attributes['android:name'].value))
                            
            else:
                if (export_val == "true"): # if there are no intent filters but the activity was exported explicitly, we do want to report it
                    is_exported = True
                    tag = "exported"
            #Check permission settings to see if we need a certain permission
            # to send broadcasts to this receiver
            permission = ""
            try:
                permission = str(item.attributes['android:permission'].value)
            except:
                # no permissions required?
                permission = "N/A"
            #printString(item.attributes['android:name'].value + " " + permission
        # final verdict for this activity
        if (is_exported):
            # it's exported, now open it and see if getIntent( or getStringExtra( appear
            activity_name = item.attributes['android:name'].value
            input_tag = ''
            if '$' not in activity_name:
                activity_path = activity_name.replace('.', "/")
                try:
                    f = open(coderoot + activity_path + '.java', 'r')
                    data = f.read()
                    f.close()
                    if ('getIntent(' in data):
                        input_tag = "getIntent"
                    if ('getDataString(' in data):
                        input_tag = "getDataString"
                except:
                    x = 1

            printString("[Activity] " + activity_name + " " + str(is_exported) + " " + tag + " " + input_tag)
            saveActivity(db, 'activities', packagename, activity_name, tag, input_tag, permission, current_time)
            for action in actions:
                saveActivityAction(db, 'activity_actions', packagename, item.attributes['android:name'].value, action, "", current_time)



# parse xml document looking for exported or available activities
def getAliases(xmldocument, db):
    items = xmldocument.getElementsByTagName("activity-alias")
    # for each alias
    for item in items:
        is_exported = ''
        tag = ''
        export_val = ''
        actions = []
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
                    
                    # now check for actions and record those. This helps us do analysis later to know what the item might be expecting
                    action_elements = intent_filter.getElementsByTagName('action')
                    if (action_elements != []):
                        for action_element in action_elements:
                            actions.append(str(action_element.attributes['android:name'].value))
                            
            else:
                if (export_val == "true"): # if there are no intent filters but the activity was exported explicitly, we do want to report it
                    is_exported = True
                    tag = "exported"
                
        # final verdict for this activity
        if (is_exported):
            # get the target
            target = str(item.attributes['android:targetActivity'].value)
            printString("[Alias] " + item.attributes['android:name'].value + " " + str(is_exported) + " " + tag + '\n\tTarget: ' + target)
            saveAlias(db, 'aliases', packagename, item.attributes['android:name'].value, target, tag, current_time)
            for action in actions:
                saveActivityAction(db, 'activity_actions', packagename, item.attributes['android:name'].value, action, "", current_time)


def scanRegex(directory, rules):
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            skip = False
            filepath = os.path.join(root, name)
            for item in blacklist:
                if item in (filepath[-5:]):
                    skip = True
            if (skip == False):
                #open file and run regex
                filedata = ""
                didRead = True
                f = open(filepath, 'r')
                try:
                    filedata = f.read()
                except:
                    # cannot read file
                    if (debug):
                        printString("[debug] Error could not read file " + filepath)
                    didRead = False
                f.close()
                #if (debug):
                #    printString("[debug] Read file: " + filepath
                if didRead:
                    for key in rules:
                        found_strings = rules[key].findall(filedata)
                        if (found_strings):
                            for found_string in found_strings:
                                try:
                                    printString('[Secrets] Detected ' + key + ' in ' + filepath)# + ', value: ' + found_string)
                                except:
                                    # encode/decode error... just tell the user we found something
                                    printString('[Secrets] Detected ' + key + ' in ' + filepath + ', value: <encoding error>')






# Start main code
parser = OptionParser('Usage: core.py -m <path to AndroidManifest.xml> -j <path to jadx decompiled app output directory> -f (/path/to/output.db) --debug --secrets --low-confidence')
parser.add_option('-j', '--jadx', dest="jadxdir", help="Directory with jadx decompiled app output")
parser.add_option('-m', '--manifest', dest="manifest", help="Path to AndroidManifest.xml")
parser.add_option("--low-confidence", action="store_true", dest="confidence", help="look for low-quality hits, such as broadcasters in files with LocalBroadcastManager imported. High false positive rate")
parser.add_option("-q", "--quiet", action="store_true", dest="quiet", help="suppress printed output")
parser.add_option("-o", "--output-file", dest="out_file", help="Write sqlite database to specified file. Default is apps.db in current directory.")
parser.add_option("--debug", dest="debug", action="store_true", help="Enable verbose debug output")
parser.add_option("--skip-code", dest="skip_code", action="store_true", default=False, help="Skip scanning code files (speeds up scan)")
parser.add_option("--secrets", dest="scan_secrets", help="JSON regex file containing search terms for API keys, tokens, and other sensitive data")

(options, args) = parser.parse_args()
out_file = options.out_file
quiet = options.quiet
debug = options.debug
scan_secrets = options.scan_secrets
jadxdir = options.jadxdir
confidence = options.confidence
manifest = options.manifest
skip_code = options.skip_code

current_time = str(time.time())

check_all = False
manifest_only = True

# check if we have manifest, resources, or both
if (manifest == None and jadxdir == None):
    printString('You must specify an input manifest file (-m) or jadx app directory (-j)')
    printString(parser.usage)
    exit()
elif (manifest == None):
    # use jadx dir and conduct full code analysis
    # override manifest variable so we can keep using it
    manifest = jadxdir + "resources/AndroidManifest.xml"


if (scan_secrets != None):
    # read in regex rules
    rule_file = open(scan_secrets, 'r')
    rule_file_data = json.loads(rule_file.read())
    enabled_rules = rule_file_data["enabled"]
    for rule in enabled_rules:
        if (debug):
            printString('[debug] Regex rule: ' + rule + " " + enabled_rules[rule])
        rules[rule] = re.compile(enabled_rules[rule])
    rule_file.close()

if (confidence):
    check_all = True
if (quiet):
    silent = True

# setup database file - default to apps.db
db_file = 'apps.db'
if (out_file != None):
    db_file = out_file

if (not os.path.exists(db_file)):
    # init tables if DB does not already exist
    conn = sqlite3.connect(db_file)
    initDB(conn)
    if (debug):
        printString("Created DB")
else:
    conn = sqlite3.connect(db_file)



#
# BEGIN ANALYSIS CODE
#

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
    has_permission = True
    try:
        perm_name = str(permission.attributes['android:name'].value)
    except:
        # permission does not exist?
        perm_name = ''
        has_permission = False
    
    if (has_permission):
        # temporarily removing the flagged_permissions check since I don't really use it
        # But, replacing with a more friendly check for custom permissions
        #if p_name in flagged_permissions:
        #    printString("Uses: " + p_name)
        #    saveItem(conn, "permissions", packagename, p_name, "", current_time)
        if perm_name.startswith('android.') == False and perm_name.startswith('com.android') == False: # if not a default permission
            printString("Unusual permission: " + perm_name)
            if (packagename in perm_name):
                tag = "custom self"
            else:
                tag = "custom 3rd party"
            saveItem(conn, "uses_permissions", packagename, perm_name, tag, current_time)
            
# defined permissions
permissions = xmldoc.getElementsByTagName('permission')
structured_output['permissions'] = []
for permission in permissions:
    has_permission = True
    try:
        perm_name = str(permission.attributes['android:name'].value)
    except:
        # permission does not exist?
        perm_name = ''
        has_permission = False
    
    if (has_permission):
        printString("Defines permission: " + perm_name)
        saveItem(conn, "defines_permissions", packagename, perm_name, "", current_time)


# Firebase URL
stringsdoc = None
strings_xml = "/resources/res/values/strings.xml"
if jadxdir[-1] == '/':
    strings_xml = "resources/res/values/strings.xml"
try:
    stringsdoc = minidom.parse(jadxdir + strings_xml)
    res = stringsdoc.getElementsByTagName('resources')[0]
    items = res.getElementsByTagName('string')
    url = None
    gapikey = None
    app_id = None
    project_id = None
    for item in items:
        s_name = str(item.attributes['name'].value)
        if (s_name == "firebase_database_url"):
            url =  str(item.firstChild.data)
            printString("Firebase Manifest URL: " + url)
        elif (s_name == "google_api_key"):
            gapikey = str(item.firstChild.data)
        elif (s_name == "google_app_id"):
            app_id = str(item.firstChild.data)
            project_id = str(app_id.split(':')[1])
            
    saveFirebaseManifest(conn, "firebase_manifest", packagename, url, app_id, project_id, gapikey, "", current_time)
except Exception as e:
    printString('[-] Error processing strings.xml: ' + str(e))
    printString("[-] Noncritical error, continuing")


# All exported components that the manifest reveals
printString('\n-- Exported Components --')

# activities
printString('')
getActivities(xmldoc, conn, jadxdir + "sources/")

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
if (jadxdir != None and skip_code == False):
    java = jadxdir + "sources/"
    if (debug):
        printString("Analzying java source code at " + java)
        printString("check_all=" + str(check_all))
    file_list = getAllFiles(java)
    for fi in file_list:
        fi_name = fi.replace(java, '')
        f = open(fi, 'r')
        filedata = f.read()
        f.close()
        item_id = fi_name.replace('/', '.')
        
        if (' WebView' in filedata):
            if (packagename in item_id):
                code_search.append('[High] Detected WebView in ' + item_id)
                saveItem(conn, 'webviews', packagename, item_id, "package-match", current_time)
            elif (check_all):
                code_search.append('Detected WebView in ' + item_id)
                saveItem(conn, 'webviews', packagename, item_id, "", current_time)


        if ('.registerReceiver()' in filedata):
            if (packagename in item_id):
                code_search.append('[High] Detected receiver in ' + item_id)
                saveItem(conn, 'runtime_receivers', packagename, item_id, "package-match", current_time)
            elif (check_all):
                code_search.append('Detected receiver in ' + item_id)
                saveItem(conn, 'runtime_receivers', packagename, item_id, "", current_time)

        if ('@JavascriptInterface' in filedata):
            if (packagename in item_id):
                code_search.append('[High] Detected Javascript Bridge in ' + item_id)
                saveItem(conn, 'jsbridges', packagename, item_id, "package-match", current_time)
            elif (check_all):
                code_search.append('Detected Javascript Bridge in ' + item_id)
                saveItem(conn, 'jsbridges', packagename, item_id, "", current_time)
                
        if ('onConsoleMessage(' in filedata):
            if (packagename in item_id):
                code_search.append('[High] Detected onConsoleMessage( in ' + item_id)
                saveItem(conn, 'jsconsoles', packagename, item_id, "package-match", current_time)
            elif (check_all):
                code_search.append('Detected onConsoleMessage( in ' + item_id)
                saveItem(conn, 'jsconsoles', packagename, item_id, "", current_time)

        if ('new ServerSocket(' in filedata):
            if (packagename in item_id):
                code_search.append('[High] Detected ServerSocket in ' + item_id)
                saveItem(conn, 'servers', packagename, item_id, "package-match", current_time)
            elif (check_all):
                code_search.append('Detected ServerSocket in ' + item_id)
                saveItem(conn, 'servers', packagename, item_id, "", current_time)

        if ('127.0.0.1' in filedata):
            if (packagename in item_id):
                code_search.append('[High] Detected 127.0.0.1 in ' + item_id)
                saveItem(conn, 'loopback', packagename, item_id, "package-match", current_time)
            elif (check_all):
                code_search.append('Detected 127.0.0.1 in ' + item_id)
                saveItem(conn, 'loopback', packagename, item_id, "", current_time)

        if ('.firebase.io' in filedata):
            if (packagename in item_id):
                code_search.append('[High] Detected firebase URL in ' + item_id)
                saveItem(conn, 'firebase', packagename, item_id, "package-match", current_time)
            elif (check_all):
                code_search.append('Detected firebase URL in ' + item_id)
                saveItem(conn, 'firebase', packagename, item_id, "", current_time)


        for item in runtime_broadcast:
            if (item in filedata and "LocalBroadcastManager" not in filedata):
                if (packagename in item_id):
                    code_search.append('[High] Detected ' + item + ' in ' + item_id)
                    saveItem(conn, 'broadcasters', packagename, item_id, "package-match", current_time)
                elif (check_all): # only return low confidence items if user did not specify only high confidence items
                    code_search.append('Detected ' + item + ' in ' + item_id)
                    saveItem(conn, 'broadcasters', packagename, item_id, "", current_time)
code_search.sort()
for result in code_search:
    printString(result)

printString('\n')
printString("Authorities seen in AndroidManifest.xml")
for auth in seen_authorities:
    if (';' in auth):
        authlist = auth.split(';')
        for a in authlist:
            printString(a)
    else:
        printString(auth)

########################
# REGEX
#
if (scan_secrets and jadxdir != None):
    #printString('-- Results for ' + app_folder + ' --'
    printString('\n-- Sensitive values --')
    #scanRegex(java, rules)
    scanRegex(jadxdir, rules)
    printString('')

conn.close()
printString("\nDone")
