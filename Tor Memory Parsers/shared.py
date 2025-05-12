import os
import argparse
import mmap
import re
import time
import csv
import base64
from typing import Callable

SPIDER_LOGO = r"""
   _____                 _             ______                       _          
  / ____|               | |           |  ____|                     (_)         
 | (___  _ __  _   _  __| | ___ _ __  | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
  \___ \| '_ \| | | |/ _` |/ _ \ '__| |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
  ____) | |_) | |_| | (_| |  __/ |    | | | (_) | | |  __/ | | \__ \ | (__\__ \
 |_____/| .__/ \__, |\__,_|\___|_|    |_|  \___/|_|  \___|_| |_|___/_|\___|___/
        | |     __/ |                                                          
        |_|    |___/ 
"""

def banner(program_name: str):
    return SPIDER_LOGO + "\n" + f"""
Tor Browser Memory Parser - {program_name}
Version: 1.0 Feb, 2025
Author: Spyder Forensics Training
Website: www.spyderforensics.com
Course: Host-Based Dark Web Forensics
"""

def run_argparser(description: str, input_help: str, output_help: str, program_name: str, program: Callable[[str, str], None]):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-i', '--input', type=str, required=True, help=input_help)
    parser.add_argument('-o', '--output', type=str, required=True, help=output_help)

    args = parser.parse_args()
    print(banner(program_name))

    if not os.path.isfile(args.input):
        print("The specified memory dump file does not exist.")
    else:
        program(args.input, args.output)