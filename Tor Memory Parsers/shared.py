import os
import argparse
import re
import mmap
import time
import csv
from typing import Callable

from records import *

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

def extract_to_csv(dump_file_path: str, output_csv_path: str, csv_headers: list[str], regex_pattern: re.Pattern[bytes], process_matcher: Callable[[int, mmap.mmap, str | None], BrowserRequest | BrowserActivity | SocksRequest | TabData | None], output_folder: str | None) -> None:
    """Reads the entire file using mmap"""
    start_time = time.time()
    print(f"Processing started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n")
    
    if output_folder:
        # Create the main output folder based on user input
        os.makedirs(output_folder, exist_ok=True)

        # Define CSV file path inside the output folder
        output_csv_path = os.path.join(output_folder, f"{os.path.basename(output_folder)}.csv")

        # Create Favicon output folder inside the main output folder
        extracted_icons_folder = os.path.join(output_folder, "Extracted FavIcons")
        os.makedirs(extracted_icons_folder, exist_ok=True)
    
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(csv_headers)

        with open(dump_file_path, 'rb') as dump_file:
            with mmap.mmap(dump_file.fileno(), 0, access=mmap.ACCESS_READ) as memory_data:
                match_offsets = sorted(match.start() for match in regex_pattern.finditer(memory_data))

                for offset in match_offsets:
                    row = process_matcher(offset, memory_data, output_folder)
                    if row:
                        csv_writer.writerow(row.to_csv_row())

    end_time = time.time()
    print(f"\nProcessing completed at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
    elapsed_time = end_time - start_time
    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f"Total execution time: {int(hours):02d}:{int(minutes):02d}:{seconds:.2f}")
    print(f"\nResults saved to: {output_csv_path}")


def run_argparser(description: str, input_help: str, output_help: str, program_name: str, csv_headers: list[str], regex_pattern: re.Pattern[bytes], process_matcher: Callable[[int, mmap.mmap, str | None], BrowserActivity | TabData | SocksRequest | BrowserRequest | None], output_folder: str):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-i', '--input', type=str, required=True, help=input_help)
    parser.add_argument('-o', '--output', type=str, required=True, help=output_help)

    args = parser.parse_args()
    print(banner(program_name))

    if not os.path.isfile(args.input):
        print("The specified memory dump file does not exist.")
    else:
        extract_to_csv(args.input, args.output, csv_headers, regex_pattern, process_matcher, output_folder)