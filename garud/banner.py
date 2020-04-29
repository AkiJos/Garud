#!/usr/bin/python3

#Author: B31212Y

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

GARUD = """
							____________    ___ 	 ____________ 
							\_____     /   /_. \     \     _____/
							 \_____    \____/   \____/    _____/
							  \_____                    _____/
							     \__________    __________/
								       /_____\				

									गरुड़
"""
print(red,GARUD,reset)
logging.info(GARUD)
