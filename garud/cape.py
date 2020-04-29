#!/usr/bin/python3 

#Author: B31212Y

# This script consumes Cape Sandbox [Base URL: https://www.capesandbox.com/api/tasks/search/ ] 
# Currently growing sandbox site which is based on Cape Sandbox [ Base URL: https://sandbox.xor.al/api/tasks/search/ ]
# The script takes input of MD5, SHA1 or SHA256 hash and searches in its DB and gives the output, script could break
# if there is any changes in the response or in the api endpoint


import requests
import json
import time
import logging

yellow = "\033[33;1m"
red = "\033[31;1m"
green = "\033[32;1m"
purple = "\033[35;1m"
reset = "\033[m"

filename = "garud.log"

logging.basicConfig(filename=filename,format = "%(message)s", level=logging.INFO)


def cape_search(htype, hinput):

	ioc_list = list()

	hash_type = htype

	h_type = str(hash_type).lower()

	hash_input = hinput
	
	#Uncomment base_url according to your need, both are using Cape Sandbox

	base_url = "https://sandbox.xor.al/api/tasks/search/" # This is another site which runs with CAPE Sandbox

	#base_url = "https://www.capesandbox.com/api/tasks/search/"


	user_agent = "AJ (Windows NT 42.0; Win42; x42; rv:42.0) Gecko/42 AJ"

	headers = {'User-Agent': user_agent}
	try:

		cape_req = requests.get(base_url + h_type + "/" + hash_input,headers=headers)
		
		if cape_req.status_code == 200:

			
			json_resp = json.loads(cape_req.text)

			#converting into dict

			print(purple,"_"*38,reset)
			logging.info("_"*38)
			print(purple, "Searching in Cape Sandbox for results",reset)
			logging.info("Searching in Cape Sandbox for results")
			print(purple,"_"*38,reset,"\n")
			logging.info("_"*38 + "\n")

			for key,val in json_resp.items():
				#print(key,":",val) #This prints data and error as key values

				if "data" in key:

					#This a list and iterating through it

					for data_key in val:

						for subkey,subval in data_key.items():
						
							
							if subkey.startswith("id"):
								
								print("Got the Task ID:", subval, "now getting IOC related to it")
								logging.info("Got the Task ID: %s now getting IOC related to it", subval)
								print("|",yellow,subkey,":",subval,reset,"|")
								logging.info("| %s: %s |",subkey,subval)
								

								# id is the key value which we are looking for and this would help in
								# extracting the detialed IOC 
						
								#Now we will extract all IOC from 
								#https://www.capesandbox.com/api/tasks/get/iocs/[task id]/detailed/

								# converting int into str subval i.e id value
								
								task_id = str(subval) + "/detailed/"
		
								# Uncomment the ioc_url based on base_url


								#ioc_url = "https://www.capesandbox.com/api/tasks/get/iocs/"

								ioc_url = "https://sandbox.xor.al/api/tasks/get/iocs/"
								ioc_req = requests.get(ioc_url + task_id, headers=headers)
								time.sleep(3)
								print("Sleeping for 3 seconds")
								if ioc_req.status_code == 200:
									json_ioc = json.loads(ioc_req.text)
									
									
									#Appending the json output in a list
									
									ioc_list.append(json_ioc)
							
									for ioc_data in ioc_list:
																	
									
										for ioc_key,ioc_val in ioc_data.items():
											if "data" in ioc_key:
											
												for data_key,data_val in ioc_val.items():
													if "malscore" in data_key:
														print(red,data_key,":",data_val,reset)
														logging.info("%s : %s", data_key,data_val)

													elif "detections" in data_key and data_val is not None:
														print(red,data_key,":",data_val,reset)
														logging.info("%s : %s", data_key,data_val)

													elif "detections" in data_key and data_val is None:
														print(green,data_key,":",data_val,reset)
													
														logging.info("%s: %s", data_key, data_val)						
													elif "process_tree" in data_key:
														print(yellow,data_key,":",reset)

														logging.info("%s: ", data_key)						
														for ptree_key,ptree_val in data_val.items():
															print("\t",yellow,ptree_key,":",purple,ptree_val,reset)

															logging.info("\t%s: %s", ptree_key,ptree_val)						
													elif "signatures" in data_key:
														print(yellow,data_key,":",reset)

														logging.info("%s: ", data_key)						
														for sig_key in data_val:
															for skey,sval in sig_key.items():
																print("\t",yellow,skey,":",purple,sval,reset)
																	
																logging.info("\t%s: %s", skey,sval)						

													elif "executed_commands" in data_key:
														print(yellow,data_key,":",reset)

														logging.info("%s: ", data_key)						
														for ecmd in data_val:
															print("\t",purple,ecmd,reset)

															logging.info("\t%s:", ecmd)						
														
													elif "network" in data_key:
														print(yellow,data_key,":",reset)
															
														logging.info("%s: ", data_key)						
														for net_key,net_val in data_val.items():
														
														
															if "traffic" in net_key:
																print("\t",yellow,net_key,":",reset)

																logging.info("\t%s: ", net_key)						
																for traffic_key,traffic_val in net_val.items():
																	print("\t"*2,purple,traffic_key,":",traffic_val,reset)

																	logging.info("\t\t%s: %s", traffic_key,traffic_val)						
															
															elif "hosts" in net_key:
																
																print("\t",yellow,net_key,":",reset)
																logging.info("\t%s", net_key)
																for net_host in net_val:
																	for net_host_key,net_host_val in net_host.items():
																		print("\t"*2,yellow,net_host_key,":",purple,net_host_val,reset)
																		logging.info("\t\t%s: %s", net_host_key,net_host_val)
															elif "domains" in net_key:
																print("\t",yellow,net_key,":",reset)
																logging.info("\t%s: ", net_key)
																for net_dom in net_val:
																	print("\t"*2,purple,net_dom,reset)
																	logging.info("\t\t%s",net_dom)

															elif "ids" in net_key:
																print("\t",yellow,net_key,":",reset)
																logging.info("\t%s", net_key)
																for ids_key,ids_val in net_val.items():
																	if ids_key.startswith("alerts"):
																		print("\t"*2,yellow,ids_key,":",reset)
																		logging.info("\t\t%s", ids_key)
																		# Now this is a list and iterating it
																		for alert_list in ids_val:
																			#Now iterating a dict
																			for al_key,al_val in alert_list.items():
																				print("\t"*3,yellow,al_key,":",purple,al_val,reset)
																				logging.info("\t\t\t%s: %s",al_key, al_val)

													elif "files" in data_key:
														print(yellow,data_key,":",reset)
														logging.info("%s: ", data_key)
														for files_key,files_val in data_val.items():
															print("\t",yellow,files_key,":",reset)
															logging.info("\t%s", files_key)
															#Now iterating the list for read, modified, deleted
															for files_attrib in files_val:
																print("\t"*2,purple,files_attrib,reset)
																logging.info("\t\t%s", files_attrib)



													elif "registry" in data_key:
														print(yellow,data_key,":",reset)
														logging.info("%s: ", data_key)
														for reg_key,reg_val in data_val.items():
															print("\t",yellow,reg_key,":",reset)
															logging.info("\t%s:", reg_key)
															#Now iterating the list for read, modified, deleted
															for reg_attrib in files_val:
																print("\t"*2,purple,reg_attrib,reset)
																logging.info("\t\t%s", reg_attrib)

													elif "mutexes" in data_key:
														print(yellow,data_key,":",reset)
														logging.info("%s:", data_key)
														for mut_list in data_val:
															print("\t",purple,mut_list,reset)
															logging.info("\t%s", mut_list)
													

													elif "dropped" in data_key:
														print(yellow,data_key,":",reset)
														logging.info("%s: ", data_key)
														for drp_list in data_val:
															for drp_key,drp_val in drp_list.items():
																print("\t",yellow,drp_key,":",purple,drp_val,reset)
																logging.info("\t%s: %s", drp_key,drp_val)

													elif "resolved_apis" in data_key:
														print(yellow,data_key,":",reset)
														logging.info("%s: ", data_key)
														for api_list in data_val:
															print("\t",purple,api_list,reset)
															logging.info("\t%s", api_list)
													
														
													elif "trid" in data_key:
														print(yellow,data_key,":",reset)
														logging.info("%s: ", data_key)
														for trid_list in data_val:
															print("\t",purple,trid_list,reset)
															logging.info("\t%s", trid_list)


													"""
													#Uncomment these lines to get the strings
													
													elif "strings" in data_key:
														print(yellow,data_key,":",reset)
														for str_list in data_val:
															print("\t",purple,str_list,reset)
													"""
													

															 
								else:
									print("Error ! Got status code for the IOC details: ", ioc_req.status_code)
							
		else:					


			
			print("Error ! Got the status code for the hash search:", cape_req.status_code)

	except: 

		print("[-] Something went wrong while searching for hash in Cape Sandbox")
		print("[*] Try searching again in the Cape Sandbox")
