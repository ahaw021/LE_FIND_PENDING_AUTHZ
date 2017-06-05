import os
import re 
import datetime as dt
import urllib3
import json
import time

from acme import client
from acme import messages
from acme import jose
from acme import challenges

PATH = r""
KEY_FOLDER = r""

CHALLENGES_REGEX = r'(?<=letsencrypt\.org\/acme\/authz\/).+?(?=\>|\s|\.)'
SUCCESS_REGEX = r'Congratulations! Your certificate'
LOG_CUTOFF_DAYS = dt.date.today() - dt.timedelta(days=30)
PRODUCTION_CA = 'https://acme-v01.api.letsencrypt.org/'
STAGING_CA = 'https://acme-staging.api.letsencrypt.org/'
challenge_re = re.compile(CHALLENGES_REGEX)
success_re = re.compile(SUCCESS_REGEX)

KEY =""
ACME_CLIENT = ''
	
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
	print('\nAnalysing File: ' + file +'\n')
	
	if(len(matches) >= 1):
		print('\tFound matches for Success Regex'+ '\n' + '\tNot Analyzing For Pending Authz\n')
		return []
		
	else:
		print('\tFound: no matches for Success Regex' + '\n' + '\tAnalyzing For Pending Authz\n')
		matches = re.findall(challenge_re,filetext)
		print('\tFound : ' + str(len(matches)) + ' Authz in file \n') 
		return matches
		
def ReviewAuthzViaHTTPS(authz):
	urllib3.disable_warnings()
	http = urllib3.PoolManager()
	for auth in authz:
		print('Reviewing Auth: ' + auth)
		
		server_response = http.request('GET',PRODUCTION_CA+ 'acme/authz/' +auth)
		json_body = json.loads(server_response.data.decode('utf-8'))
		print('\t Status:' + json_body["status"]+' Domain: ' + json_body["identifier"]["value"] +'  Expires: ' + json_body["expires"])
		if(json_body["status"] == 'pending'):
			print('Invalidating :'+auth)
			InvalidateAuth(json_body["challenges"][0]["uri"] , json_body["challenges"][0]["token"])
		print('')
		time.sleep(1)
		
def MakeACMEJOSEKey():
	path = os.path.join(KEY_FOLDER, "private_key.json")
	textfile = open(path,'r')
	filetext = textfile.read()
	textfile.close()
	global KEY 
	KEY = jose.JWK.json_loads(filetext)
	global ACME_CLIENT
	ACME_CLIENT = client.Client(PRODUCTION_CA+'directory', KEY)

def InvalidateAuth(challenge_uri, challenge_token):
	HTTPChallenge = challenges.HTTP01(token=jose.decode_b64jose(challenge_token))
	authorization = HTTPChallenge.validation(KEY)
	HTTPChallengeResponse = challenges.HTTP01Response(key_authorization=authorization)
	challenge_body = messages.ChallengeBody(chall=HTTPChallenge,uri=challenge_uri)
	answer = ACME_CLIENT.answer_challenge(challenge_body,HTTPChallengeResponse)

MakeACMEJOSEKey()			
for files in os.listdir(PATH):
	if(FirstFilePass(files)):
		authz = ExtractAuthz(files)
		ReviewAuthzViaHTTPS(authz)
