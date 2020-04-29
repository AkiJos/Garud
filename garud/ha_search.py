#!/usr/bin/python3

import requests
import json
import argparse
import logging

#Author: B31212Y

# This script consumes Falcon Sandbox Public API 2.10.0 [ Base URL: hybrid-analysis.com/api/v2 ]
# The script takes input of MD5, SHA1 or SHA256 hash and searches in its DB and gives the output, script could break
# if there is any changes in the response or in the api endpoint.




yellow = "\033[33;1m"
red = "\033[31;1m"
green = "\033[32;1m"
purple = "\033[35;1m"
blue = "\033[34;1m"
cyan = "\033[36;1m"
reset = "\033[m"

filename = "garud.log"

logging.basicConfig(filename=filename,format = "%(message)s", level=logging.INFO)


def hybrid_search(key,s_hash):
	#s_hash = input("Enter the hash value: ")

	hash_field = {'hash': s_hash}	

	hash_url = "https://hybrid-analysis.com/api/v2/search/hash"

	user_agent = "AJ (Windows NT 42.0; Win42; x42; rv:42.0) Gecko/42 AJ"

	apikey = key

	headers = {'User-Agent': user_agent, 'api-key': apikey }
	try:
		ha_req = requests.post(hash_url, headers=headers, data=hash_field)
		
		if ha_req.status_code == 200:

			json_resp = json.loads(ha_req.text)
			print(purple,"_"*42,reset)
			logging.info("*"*42)
			print(purple,"Searching in Hybrid Analysis for results",reset)
			logging.info("Searching in Hybrid Analysis for results")
			print(purple,"_"*42,reset,"\n")
			logging.info("*"*42 + "\n")

			# Apparently this is a list

			for resp_key in json_resp:
				# Now this is a dict

				for key,val in resp_key.items():
					
						if "threat_score" in key and val is None:
							print(yellow,key, ":", val,reset)
							logging.info("%s: %s", key,val)
										
						elif "threat_score" in key and val < 25:
							print(purple, key, ":", val, reset) 
							logging.info("%s: %s", key,val)
							
						elif "threat_score" in key and val < 50:
							print(yellow, key,":", val, reset)
							logging.info("%s: %s", key,val)
						elif "threat_score" in key and val > 80:
							print(red, key, ":", val, reset)
							
							logging.info("%s: %s", key,val)

						elif "verdict" in key and val == 'malicious':
							print(red,key , ":", val,reset)
							
							logging.info("%s: %s", key,val)
						elif "md5" in key:
							print(blue,key, ":", val,reset)
							
							logging.info("%s: %s", key,val)
						elif "compromised_hosts" in key:
							print(yellow,key, ":", reset)
							
							logging.info("%s: ", key)
							for host_val in val:
								print("\t",purple,host_val,reset)
								logging.info("\t%s:", host_val)

						elif "ssdeep" in key:
							print(blue,key, ":", val,reset)
							
							logging.info("%s: %s", key,val)
								
						elif "classification_tags" in key:
							print(yellow,key, ":",reset)

							logging.info("%s: ", key)
							for ctags in val:
								print("\t",purple,ctags,reset)
								
								logging.info("\t%s:", ctags)
						elif "av_detect" in key:
							print(purple,key, ":", val,reset)
								
							logging.info("%s: %s", key,val)
						elif "sha256" in key:
							print(blue,key, ":", val,reset)
							
							logging.info("%s: %s", key,val)
						
						elif "size" in key:
							print(yellow,key, ":", val,reset)
							
							logging.info("%s: %s", key,val)
						elif "mitre_attcks" in key:
							print(red,key, ":",reset)
							logging.info("%s:", key)
							for matks in val:
								for mkey,mval in matks.items():
									print("\t",red,mkey,reset,":",purple,mval,reset)
									logging.info("\t%s: %s",mkey, mval)
								
						elif "analysis_start_time" in key:
							print(blue,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "job_id" in key:
							print(purple,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "submit_name" in key:
							print(purple,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "imphash" in key:
							print(cyan,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "type_short" in key:
							print(yellow,key, ":",reset)
							
							logging.info("%s: ", key)
							for ts in val:
								print("\t", purple,ts,reset)
						
								logging.info("\t%s",ts)
						elif "environment_description" in key:
							print(yellow,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "sha1" in key:
							print(blue,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "sha512" in key:
							print(blue,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "type" in key and not "error_type" in key:
							print(yellow,key, ":", val,reset)
						
							logging.info("%s: %s", key,val)
						elif "tags" in key:
							print(purple,key, ":",reset)

							logging.info("%s: ", key)
							for tg in val:
								print("\t", purple,tg,reset)
						
								logging.info("\t%s", tg)
						elif "hosts" in key:
							print(yellow,key, ":",reset)

							logging.info("%s: ", key)
							for hst in val:
								print("\t",purple,hst,reset)
								logging.info("\t%s", hst)
						
						elif "domains" in key:
							print(yellow,key, ":",reset)

							logging.info("%s: ", key)
							for dn in val:
								print("\t",purple,dn,reset)

								logging.info("\t%s ", dn)
						
						elif "vx_family" in key:
							print(red,key, ":", val,reset)

							logging.info("%s: %s", key,val)
						
						elif "compromised_hosts" in key:
							print(purple,key, ":", val,reset)

							logging.info("%s: %s", key,val)
							
							

		else:					

			print("Error ! Got the status code for the hash search:", ha_req.status_code)



	except:
		print("[-]something went wrong while searching for hash in Hybrid Analysis")
