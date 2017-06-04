import os
import re 
import datetime as dt
import urllib3
import json

PATH = '.'
CHALLENGES_REGEX = r'(?<=letsencrypt\.org\/acme\/authz\/).+'
SUCCESS_REGEX = r'Congratulations! Your certificate'
LOG_CUTOFF_DAYS = dt.date.today() - dt.timedelta(days=7)
PRODUCTION_CA = 'https://acme-v01.api.letsencrypt.org/acme/authz/'
STAGING_CA = 'https://acme-staging.api.letsencrypt.org/acme/authz/'

challenge_re = re.compile(CHALLENGES_REGEX)
success_re = re.compile(SUCCESS_REGEX)

	
#first pass function will cull out files that are older than 7 days
	
def FirstFilePass(file):
	fileTimeStamp = dt.date.fromtimestamp(os.path.getmtime(file))
	if(fileTimeStamp > LOG_CUTOFF_DAYS):
		return True
	else:
		return False

def ExtractAuthz(file):
	textfile = open(file, 'r')
	filetext = textfile.read()
	textfile.close()
	matches = re.findall(success_re, filetext)
	#print('\nAnalysing File: ' + file +'\n')
	
	if(len(matches) >= 1):
		#print('\tFound matches for Success Regex'+ '\n' + '\tNot Analyzing For Pending Authz\n')
		return []
		
	else:
		#print('\tFound: no matches for Success Regex' + '\n' + '\tAnalyzing For Pending Authz\n')
		matches = re.findall(challenge_re,filetext)
		#print('\tFound : ' + str(len(matches)) + ' Authz in file \n') 
		return matches
		
def ReviewAuthzViaHTTPS(authz):
	urllib3.disable_warnings()
	http = urllib3.PoolManager()
	for auth in authz:
		print('Reviewing Auth: ' + auth)
		server_response = http.request('GET',STAGING_CA+auth)
		json_body = json.loads(server_response.data.decode('utf-8'))
		if(json_body["status"] == 'pending'):
			print('\t Status:' + json_body["status"]+' Domain: ' + json_body["identifier"]["value"] +'  Expires: ' + json_body["expires"])
		print('')	
		
			
for files in os.listdir(PATH):
	if(FirstFilePass(files)):
		authz = ExtractAuthz(files)
		ReviewAuthzViaHTTPS(authz)
		
	import os
import re 
import datetime as dt
import urllib3
import json

PATH = '.'
CHALLENGES_REGEX = r'(?<=letsencrypt\.org\/acme\/authz\/).+'
SUCCESS_REGEX = r'Congratulations! Your certificate'
LOG_CUTOFF_DAYS = dt.date.today() - dt.timedelta(days=7)
PRODUCTION_CA = 'https://acme-v01.api.letsencrypt.org/acme/authz/'
STAGING_CA = 'https://acme-staging.api.letsencrypt.org/acme/authz/'

challenge_re = re.compile(CHALLENGES_REGEX)
success_re = re.compile(SUCCESS_REGEX)

	
#first pass function will cull out files that are older than 7 days
	
def FirstFilePass(file):
	fileTimeStamp = dt.date.fromtimestamp(os.path.getmtime(file))
	if(fileTimeStamp > LOG_CUTOFF_DAYS):
		return True
	else:
		return False

def ExtractAuthz(file):
	textfile = open(file, 'r')
	filetext = textfile.read()
	textfile.close()
	matches = re.findall(success_re, filetext)
	#print('\nAnalysing File: ' + file +'\n')
	
	if(len(matches) >= 1):
		#print('\tFound matches for Success Regex'+ '\n' + '\tNot Analyzing For Pending Authz\n')
		return []
		
	else:
		#print('\tFound: no matches for Success Regex' + '\n' + '\tAnalyzing For Pending Authz\n')
		matches = re.findall(challenge_re,filetext)
		#print('\tFound : ' + str(len(matches)) + ' Authz in file \n') 
		return matches
		
def ReviewAuthzViaHTTPS(authz):
	urllib3.disable_warnings()
	http = urllib3.PoolManager()
	for auth in authz:
		print('Reviewing Auth: ' + auth)
		server_response = http.request('GET',STAGING_CA+auth)
		json_body = json.loads(server_response.data.decode('utf-8'))
		if(json_body["status"] == 'pending'):
			print('\t Status:' + json_body["status"]+' Domain: ' + json_body["identifier"]["value"] +'  Expires: ' + json_body["expires"])
		print('')	
		
			
for files in os.listdir(PATH):
	if(FirstFilePass(files)):
		authz = ExtractAuthz(files)
		ReviewAuthzViaHTTPS(authz)
		
	
