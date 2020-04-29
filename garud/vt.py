#!/usr/bin/python3

#Author: B31212Y

# This script consumes VirusTotal Public API [ Base URL: https://www.virustotal.com/api/v3/files/ ]
# The script takes input of MD5, SHA1 or SHA256 hash and searches in its DB and gives the output, script could break
# if there is any changes in the response or in the api endpoint


import json
import requests
import logging

yellow = "\033[33;1m"
red = "\033[31;1m"
green = "\033[32;1m"
purple = "\033[35;1m"
blue = "\033[34;1m"
cyan = "\033[36;1m"
reset = "\033[m"

filename = "garud.log"

logging.basicConfig(filename=filename,format = "%(message)s", level=logging.INFO)


def vt_search(key, s_hash):

	hash_val = s_hash

	vt_url = "https://www.virustotal.com/api/v3/files/"

	user_agent = "AJ (Windows NT 42.0; Win42; x42; rv:42.0) Gecko/42 AJ"


	apikey = key

	headers = {'User-Agent': user_agent, 'x-apikey': apikey}

	try:
		vt_req = requests.get(vt_url + hash_val,headers=headers)

		if vt_req.status_code == 200:
			
			json_resp = json.loads(vt_req.text)

			print(purple,"_"*36,reset)
			logging.info("_"*36)
			print(purple,"Searching in Virustotal for result",reset)
			logging.info("Searching in VirusTotal for result")
			print(purple,"_"*36,reset,"\n")
			logging.info("_"*36 + "\n")

			#converting into dict

			for key,val in json_resp.items():
				#print(key) This prints data

				for subkey,subval in val.items():
					
				# Key value which is of our interest is attribute hence moving to that key value items
					
					if "attributes" in subkey:
						
						for key_attr,val_attr in subval.items():
							
							
							
							if "last_submission_date" in key_attr:
								print(yellow,key_attr,":", val_attr,reset)
								logging.info("%s: %s", key_attr,val_attr)						
													
								
							elif "last_analysis_stats" in key_attr:
								print(yellow,key_attr,":", reset)
								
								logging.info("%s: ", key_attr)						
								for lst_an_key,lst_an_val in val_attr.items():
									print("\t",yellow,lst_an_key,":",purple,lst_an_val,reset)

									logging.info("\t%s: %s", lst_an_key,lst_an_val)						
							elif "first_submission_date" in key_attr:
								print(yellow,key_attr,":", val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "last_modification_date" in key_attr:
								print(yellow,key_attr,":", val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "vhash" in key_attr:
								print(cyan,key_attr,":", val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "size" in key_attr:
								print(yellow,key_attr,":", val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "sha256" in key_attr:
								print(cyan,key_attr,":", val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						


							elif "sha1" in key_attr:
								print(cyan,key_attr,":", val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "ssdeep" in key_attr:
								print(cyan,key_attr,":", val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						
							

							elif "trid" in key_attr:
								print(yellow,key_attr, ":",reset)

								logging.info("%s: ", key_attr)						
								for tr_val in val_attr:
									for trid_key,trid_val in tr_val.items():
										print("\t",yellow,trid_key,":",purple,trid_val,reset)

										logging.info("%s: %s", trid_key,trid_val)						

							elif "authentihash" in key_attr:
								print(cyan,key_attr,":",val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						


							elif "magic" in key_attr:
								print(yellow,key_attr,":",purple,val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "md5" in key_attr:
								print(cyan,key_attr,":",val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							#This can be uncommented if pe_info is required and parse it accordingly

							#elif "pe_info" in key_attr:
							#	print(yellow,key_attr,":",val_attr,reset)


							elif "last_analysis_results" in key_attr:
								print(yellow,key_attr,":",reset)
								
								logging.info("%s: ", key_attr)						
								for res_key,res_val in val_attr.items():
									#print(purple,res_key,":123test",reset)
									for eng_key,eng_val in res_val.items():
										
										if "result" in eng_key and eng_val is not None:
											print("\t",purple,res_key,":",reset)

											logging.info("\t%s: ", res_key)						
											print("\t",red,eng_key,":",eng_val,reset)
										
											logging.info("\t%s: %s", eng_key,eng_val)						

							elif "type_tag" in key_attr:
								print(yellow,key_attr,":",purple,val_attr,reset)
									
								logging.info("%s: %s", key_attr,val_attr)						
							
							elif "tags" in key_attr:
								print(yellow,key_attr,":",reset)

								logging.info("%s: ", key_attr)						
								for tag_items in val_attr:
									print("\t",yellow,tag_items,reset)

									logging.info("\t%s", tag_items)						
							
							elif "last_analysis_date" in key_attr:
								print(yellow,key_attr,":",val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						
							
							elif "names" in key_attr:
								print(yellow,key_attr,":",reset)

								logging.info("%s: ", key_attr)						
								for nam_items in val_attr:
									print("\t",yellow,nam_items,reset)

									logging.info("\t%s", nam_items)						
							elif "creation_date" in key_attr:
								print(yellow,key_attr,":",val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "times_submitted" in key_attr:
								print(yellow,key_attr,":",val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							
							elif "packers" in key_attr:
								print(yellow,key_attr,":",reset)

								logging.info("%s: ", key_attr)						
								for pack_key,pack_val in val_attr.items():
									print("\t",yellow,pack_key,":",purple,pack_val,reset)	

									logging.info("\t%s: %s", pack_key,pack_val)						

							elif "exiftool" in key_attr:
								print(yellow,key_attr,":",reset)

								logging.info("%s: ", key_attr)						
								for exif_key,exif_val in val_attr.items():
									print("\t",yellow,exif_key,":",purple,exif_val,reset)	

									logging.info("%s: %s", exif_key,exif_val)						

							elif "meaningful_name" in key_attr:
								print(yellow,key_attr,":",val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						

							elif "signature_info" in key_attr:
								print(yellow,key_attr,":",reset)

								logging.info("%s: ", key_attr)						
								for sinfo_key,sinfo_val in val_attr.items():
									print("\t",yellow,sinfo_key,":",purple,sinfo_val,reset)

									logging.info("%s: %s", sinfo_key,sinfo_val)						

							elif "type_description" in key_attr:
								print(yellow,key_attr,":",val_attr,reset)

								logging.info("%s: %s", key_attr,val_attr)						
		else:
			print("Error ! Got the status code for the hash search:", vt_req.status_code)
							
		

	except:
		print("[-] Something went wrong while searching in VT")
