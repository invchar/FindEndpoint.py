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
	while x < 2:
		swsess.sendline(userpw)
		i = swsess.expect(['#', 'Password:'])
		if i == 0:
			return
		elif i == 1:
			userpw = getpass.getpass('Wrong user password, try again: ')
			x = x + 1 
	print('Too many failed attempts.')
	quit()
	
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
	if hit[3] in swsess.before.decode(encoding='UTF-8'): #If the interface shows in show interfaces trunk, it is a trunk
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
		cdpinfo = str.split(swsess.before.decode(encoding='UTF-8'), '\n') #Split on new lines
		i = 0
		for line in cdpinfo:
			cdpinfo[i] = line.split() #Split lines on whitespace
			i = i + 1 #Increment for index
		#Find IPs of neighbor switches
		i = len(cdpinfo) - 1
		while i >= 0: #Start at end of list and work backward so lines being removed don't mess up loop counter
			if len(cdpinfo[i]) >= 1: #If it is a line with at least one word
				if cdpinfo[i][0] == 'Management': #If we get to a Management IPs section
					switches.append(cdpinfo[i + 1][2]) #Add the IP to the list of IPs to return
			i = i - 1 #Count down loop counter
		return switches
	else:
		swsess.sendline('show cdp neighbors detail')
		swsess.expect('#')
		#Split up the show command output and get just useful lines
		cdpinfo = str.split(swsess.before.decode(encoding='UTF-8'), '\n') #Split on new lines
		i = 0
		for line in cdpinfo:
			cdpinfo[i] = line.split() #Split lines on whitespace
			i = i + 1 #Increment for index
		#Find IP of switch at other end of trunk
		i = len(cdpinfo) - 1
		while i >= 0: #Start at end of list and work backward so lines being removed don't mess up loop counter
			if len(cdpinfo[i]) >= 2: #If it is a line with at least two words
				if cdpinfo[i][1] == toget.replace('Gi','GigabitEthernet') + ',': #If the line matches the interface we're looking for
					return cdpinfo[i - 2][2] #Return the IP to be appended to the switch list
			i = i - 1 #Count down loop counter

### Define check sw (runs through the checks for a switch, calling above functions as necessary to get info)
def checksw(ipaddy):
	global swsess #The current ssh session to the current switch
	global hit #Will be line from mac address table if it has target MAC
	global swnum
	global swlist
	othermacs = []
	otherswitches = []
	
	#Spawn ssh session
	swsess = pexpect.spawn('ssh ' + usernm + '@' + ipaddy)
	
	#Check if switch key fingerprint is known host, if not, ask if acceptable
	i = swsess.expect(['\?', 'Password:'])
	if i == 0:
		print(swsess.before.decode(encoding='UTF-8'))
		answer = input('Answer: ')
		if answer == 'yes':
			swsess.sendline('yes')
			swsess.expect('Password:')
		else:
			print('Not accepting fingerprint. Quitting.')
			quit()

	#Initial switch login
	initlogin()
	
	#Elevate to privileged exec (necessary for some show commands)
	#privexec() #doesn't appear needed after all - at least in our env
	
	#Set term length to zero to eliminate 'more' prompts
	termlen('off')
	
	#Check MAC table for target MAC
	hit, othermacs = checkmactable()
	
	if hit != '0': #if there was a hit (MAC found in address table)
		if ismacontrunk(): #If the MAC is on a trunk we need to follow the trail to the next switch
			nextsw = checkcdpinfo(hit[3]) #Get IP of next switch from cdp info
			if nextsw not in swlist: #If the next switch isn't already in the switch list, otherwise we could loop around
				swlist.insert(swnum + 1, nextsw) #Insert switch to be next in line to check
			else: #If it IS in swlist, see if it has already been checked, and if not, bump it up in the list to be next
				if swlist.index(nextsw) > swnum:
					swlist.insert(swnum + 1, swlist.pop(nextsw))
		else: #If the MAC is on an access port, we have found what we wanted
			print('Target MAC ' + targetmac + ' found on access port ' + hit[3] + ' on switch at ' + ipaddy)
			if othermacs: #If other macs were found on the same port, let's list them out
				print('Other MACs found on the same port are: ')
				print(othermacs)
			quit()
	else: #If no hit, get IPs of all neighboring switches and add them to the switch list
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

