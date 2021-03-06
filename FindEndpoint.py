#!/usr/bin/env python3

#imports
import string
import pexpect
import getpass

global usernm
global userpw
global enablepw
global targetmac
global swsess
global swlist
global swnum
global hit

#Get input for switch connections
swlist = [input('Start switch (typically stp root): ')] #Discovered switches will be added to this list as necessary
swnum = 0 #Incremented as switches in the list are checked to move on to next switch
usernm = input('Username (needs to have access on all switches): ')
userpw = getpass.getpass('User password: ')
#enablepw = getpass.getpass('Enable password: ') #Needed to get cdp neighbor detail
targetmac = input('Target MAC (xxxx.xxxx.xxxx): ')
hit = '0'


### Define termlen (set terminal length on switch)
def termlen(action):
	global swsess
	if action == "off":
		swsess.sendline('terminal length 0')
		swsess.expect('#')
	elif action == "on":
		swsess.sendline('no terminal length 0')
		swsess.expect('#')
	else:
		print('Invalid argument passed to termlen')
	return

### Define initlogin (initial switch login)
def initlogin():
	x = 0
	global swsess
	global userpw
	global swnum
	global swlist
	global usernm
	while x < 2:
		swsess.sendline(userpw)
		i = swsess.expect(['#', 'Password:'])
		if i == 0:
			return 0
		elif i == 1:
			a = input('Wrong credentials on switch ' + swlist[swnum] + ' using username ' + usernm +  ', [try] again or [skip]?')
			if a == 'try':
				userpw = getpass.getpass('Wrong credentials on switch ' + swlist[swnum] + ' using username ' + usernm +  ', try again: ')
				x = x + 1 
			else:
				return 1
	print('Too many failed attempts, skipping this switch')
	return 1
	
### Define privexec (elevate to privileged exec on switch)
def privexec():
	x = 0
	global swsess
	global enablepw
	while x < 2:
		swsess.sendline('enable') 
		swsess.expect('Password:')
		swsess.sendline(enablepw)
		i = swsess.expect(['#', 'denied'])
		if i == 0:
			return
		elif i == 1:
			enablepw = getpass.getpass('Wrong enable password, try again: ')
			x = x + 1
	print('Too many failed attempts.')
	quit()

### Define checkmactable (checks MAC address table for target MAC, returns hit line or string '0'
def checkmactable():
	global swsess
	othermacs = []
	#Get the mac address table
	swsess.sendline('show mac address-table')
	swsess.expect('#')

	#Split up the show command output and get just useful lines
	showmacdata = str.split(swsess.before.decode(encoding='UTF-8'), '\n') #Split on new lines
	i = 0
	for line in showmacdata:
		showmacdata[i] = line.split() #Split lines on whitespace
		i = i + 1 #Increment for index

	#Get rid of useless lines
	i = len(showmacdata) - 1
	while i >= 0: #Start at end of list and work backward so lines being removed don't mess up loop counter
		if showmacdata[i]: #If it isn't a blank line
			if showmacdata[i][0].isdigit(): #If the line begins with a digit (which will be a vlan number)
				i = i - 1 #Count down loop counter
				continue #Don't remove the line, go to next loop iteration
		showmacdata.pop(i) #Remove line from list
		i = i - 1 #Count down loop counter

	#Check lines for target MAC
	for line in showmacdata:
		if line[1] == targetmac: #If the MAC address in the line matches our target MAC	
			hit = line #Keep the line in a variable so we can check other things
			print('See MAC on port ' + hit[3] + ' on switch at ' + swlist[swnum])
			#See if there are other MACs on the access port, and if there are, list them
			for line in showmacdata:
				if line[3] == hit[3] and line[1] != targetmac:
					othermacs.append(line[1])
			return hit, othermacs
	return '0','0'

### Define ismacontrunk (checks if the hit port is a trunk, returns 1 if yes or 0 if no)
def ismacontrunk():
	global swsess
	swsess.sendline('show interfaces trunk')
	swsess.expect('#')
	if hit[3] in str.split(swsess.before.decode(encoding='UTF-8')): #If the interface shows in show interfaces trunk, it is a trunk. string split is necessary
		print(hit[3] + ' is a trunk')
		return 1 #Return true
	else:
		return 0 #Return false

### Define checkcdpinfo (Checks CDP info for IPs of other switches, returns list
def checkcdpinfo(toget):
	if toget == 'all':
		switches = []
		swsess.sendline('show cdp neighbors detail')
		swsess.expect('#')
		#First split on cdp output divider (-------------------------)
		cdpinfo = str.split(swsess.before.decode(encoding='UTF-8'), '-------------------------')
		#Next keep only lines (entries between dividers) which are for a switch (WS-)
		i = len(cdpinfo) - 1
		while i >= 0:
			if 'WS-' not in cdpinfo[i]:
				cdpinfo.pop(i)
			i = i - 1
		#split on newline instead of output divider
		cdpinfo = str.split("".join(cdpinfo), '\n')

		#Split lines on whitespace
		i = 0
		x = 0
		for line in cdpinfo:
			cdpinfo[i] = line.split() 
			i = i + 1 #Increment for index
		#Find IPs of neighbor switches
		i = len(cdpinfo) - 1
		while i >= 0: #Start at end of list and work backward so lines being removed don't mess up loop counter
			if len(cdpinfo[i]) >= 2: #If it is a line with at least two words
				if cdpinfo[i][0] == 'Management' and cdpinfo[i][1] == 'address(es):': #If we get to a Management IPs section
					if len(cdpinfo[i + 1]) >= 2:
						switches.append(cdpinfo[i + 1][2]) #Add the IP to the list of IPs to return
			i = i - 1 #Count down loop counter
		return switches
	else:
		swsess.sendline('show cdp neighbors detail')
		swsess.expect('#')
		#First split on cdp output divider (-------------------------)
		cdpinfo = str.split(swsess.before.decode(encoding='UTF-8'), '-------------------------')
		#Next keep only lines (entries between dividers) which are for a switch (WS-)
		i = len(cdpinfo) - 1
		while i >= 0:
			if 'WS-' not in cdpinfo[i]:
				cdpinfo.pop(i)
			i = i - 1
		#split on newline instead of output divider
		cdpinfo = str.split("".join(cdpinfo), '\n')

		#Split lines on whitespace
		i = 0
		for line in cdpinfo:
			cdpinfo[i] = line.split() 
			i = i + 1
		#Find IP of switch at other end of trunk
		i = len(cdpinfo) - 1
		while i >= 0: #Start at end of list and work backward so lines being removed don't mess up loop counter
			if len(cdpinfo[i]) >= 2: #If it is a line with at least two words
				if cdpinfo[i][1] == toget.replace('Gi','GigabitEthernet') + ',': #If the line matches the interface we're looking for
					return cdpinfo[i - 2][2] #Return the IP to be appended to the switch list
			i = i - 1 #Count down loop counter
		print('Unable to find next switch via cdp info, switch connected to port ' + toget)
		quit()

### Define check sw (runs through the checks for a switch, calling above functions as necessary to get info)
def checksw(ipaddy):
	global swsess #The current ssh session to the current switch
	global hit #Will be line from mac address table if it has target MAC
	global swnum
	global swlist
	othermacs = []
	otherswitches = []
	
	#Spawn ssh session
	print('Connecting to ' + usernm + '@' + ipaddy)
	swsess = pexpect.spawn('ssh ' + usernm + '@' + ipaddy)
	
	#Check if switch key fingerprint is known host, if not, ask if acceptable
	try:	
		i = swsess.expect(['\?', 'Password:'])
		if i == 0:
			print(swsess.before.decode(encoding='UTF-8'))
			answer = input('Answer: ')
			if answer == 'yes':
				swsess.sendline('yes')
				swsess.expect('Password:')
			else:
				print('Not accepting fingerprint, skipping switch ' + ipaddy)
				swnum = swnum + 1
				return
	except pexpect.TIMEOUT:
		print('Timeout reaching ' + ipaddy)
		swnum = swnum + 1
		return
	except:
		print('Some exception has occurred, moving to next switch...')
		swnum = swnum + 1
		return

	#Initial switch login
	f = initlogin()
	if f:
		swnum = swnum + 1
		return
	
	#Elevate to privileged exec (necessary for some show commands)
	#privexec() #doesn't appear needed after all - at least in our env
	
	#Set term length to zero to eliminate 'more' prompts
	termlen('off')
	
	#Check MAC table for target MAC
	hit, othermacs = checkmactable()
	
	if hit != '0': #if there was a hit (MAC found in address table)
		if ismacontrunk(): #If the MAC is on a trunk we need to follow the trail to the next switch
			nextsw = checkcdpinfo(hit[3]) #Get IP of next switch from cdp info
			if nextsw:
				if nextsw not in swlist: #If the next switch isn't already in the switch list, otherwise we could loop around
					print('Adding ' + nextsw + ' to switch list')
					swlist.insert(swnum + 1, nextsw) #Insert switch to be next in line to check
				else: #If it IS in swlist, see if it has already been checked, and if not, bump it up in the list to be next
					print('Switch ' + nextsw + ' already in list, moving to top')
					if swlist.index(nextsw) > swnum:
						swlist.insert(swnum + 1, swlist.pop(nextsw))
		else: #If the MAC is on an access port, we have found what we wanted
			print('Target MAC ' + targetmac + ' found on access port ' + hit[3] + ' on switch at ' + ipaddy)
			if othermacs: #If other macs were found on the same port, let's list them out
				print('Other MACs found on the same port are: ')
				print(othermacs)
			quit()
	else: #If no hit, get IPs of all neighboring switches and add them to the switch list
		print('Target MAC not found on ' + ipaddy)
		otherswitches = checkcdpinfo('all')
		for switch in otherswitches:
			if switch not in swlist: #If the next switch isn't already in the switch list (otherwise we could loop around forever)
				print('Adding ' + switch + ' to switch list')
				swlist.append(switch)

	hit = '0' #Reset hit
	termlen('on') #Set term length back to default on this switch
	swnum = swnum + 1 #Done getting info from this switch, increment switch counter
	
###Define main
def main():
	while 0 < 1: #Loop forever
		if len(swlist) == swnum: #If we've checked all the switches in the list
			print('Reached end of switch list')
			quit()
		if swlist[swnum]:
			checksw(swlist[swnum])

if __name__ == "__main__":
	main()

