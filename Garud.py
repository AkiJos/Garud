#!/usr/bin/python3

#Author: B31212Y

# My attempt on searching for hash in online sites. 
# Currently the Garud supports and parse's data from Hybrid Analysis, VirusTotal, Cape Sandbox.
# Output will be logged into garud.log file


import argparse

from argparse import RawTextHelpFormatter


from garud import ha_search,vt,cape

def main():

	parser = argparse.ArgumentParser(description="""


							____________    ___ 	 ____________ 
							\_____     /   /_. \     \     _____/
							 \_____    \____/   \____/    _____/
							  \_____                    _____/
							     \__________    __________/
								       /_____\				

									गरुड़
																			


	""",formatter_class=RawTextHelpFormatter)

	requiredArgs = parser.add_argument_group("Required Arguments")

	optArgs = parser.add_argument_group("Arguments")


	optArgs.add_argument('--ha_key', action="store", help="Pass the Hybrid Analysis API Key", required=False)

	optArgs.add_argument('--vt_key', action="store", help="Pass the VriusTotal API Key", required=False)

	requiredArgs.add_argument('--hash', action="store", help="Enter the hash value MD5/sha1/sha256", required=True)

	optArgs.add_argument('--hash_val', action="store", help="Enter the Hash type to pass in Cape Sandbox", required=False)

	args = parser.parse_args()

	ha_key = args.ha_key
	vt_key = args.vt_key
	hash_input = args.hash
	hash_type = args.hash_val
	
	from garud import banner
	if ha_key:

		ha_search.hybrid_search(ha_key,hash_input)
				
	if vt_key:

		vt.vt_search(vt_key,hash_input)
				
	if hash_type:
		
		cape.cape_search(hash_type,hash_input)

if __name__ =="__main__":
	
	main()
