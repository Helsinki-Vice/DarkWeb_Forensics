import os
import argparse
import mmap
import re
import time
import csv

from shared import banner

# Pre-compile patterns for efficiency
patterns = [
    b'\x02\x00\x00\x00\xF8\x01\x00\x00\x4F\x5E',
    b'\x02\x00\x00\x00\xF8\x00\x00\x00\x4F\x5E',
    b'\x02\x00\x00\x00\xF8\x03\x00\x00\x4F\x5E',
]
pattern_re = re.compile(b'|'.join(re.escape(p) for p in patterns))  # Join patterns into one regex

def process_match(match_offset, memory_data, csv_writer):
    """Processes pattern match within memory dump and writes to CSV only if required fields exist."""
    try:
        matched_prefix = memory_data[match_offset:match_offset + 9]
    except IndexError:
        return  

    index = match_offset + 9 

    if matched_prefix:
        private_browsing_id = ""
        first_party_domain = ""
        requested_resource = ""  
        entry_type = "Browser Request" 

        # Extract Private Browsing ID (Required)
        private_start = memory_data.find(b'privateBrowsingId=', index)
        if private_start == -1 or private_start > index + 100:
            return  

        private_id_start = private_start + len(b'privateBrowsingId=')
        private_browsing_id_byte = memory_data[private_id_start:private_id_start+1]

        try:
            private_browsing_id = private_browsing_id_byte.decode('utf-8')
            if not private_browsing_id.isprintable():
                private_browsing_id = f"[Non-printable: {private_browsing_id_byte.hex()}]"
        except UnicodeDecodeError:
            private_browsing_id = f"[Non-printable: {private_browsing_id_byte.hex()}]"

        index = private_id_start + 1

        # Extract First Party Domain (Required)
        first_party_start = memory_data.find(b'firstPartyDomain=', index)
        if first_party_start == -1:
            return  

        first_party_start += len(b'firstPartyDomain=')
        first_party_end = memory_data.find(b'\x2C', first_party_start)
        if first_party_end == -1:
            return  

        first_party_domain = memory_data[first_party_start:first_party_end].decode(errors='ignore').strip()
        index = first_party_end + 1

        # Extract Requested Resource (Optional)
        requested_resource_start = memory_data.find(b'\x70\x2C\x3A', index)
        if requested_resource_start != -1:
            requested_resource_start += 3
            requested_resource_end = memory_data.find(b'\x00', requested_resource_start)
            if requested_resource_end != -1:
                requested_resource = memory_data[requested_resource_start:requested_resource_end].decode(errors='ignore').strip()
                index = requested_resource_end + 1
        
        # Set Type as "Partially Recovered" if only required fields are found
        if requested_resource == "":
            entry_type = "Partially Carved Browser Request"

        print(f"[+] {entry_type} Identified at offset {match_offset}")

        # Write Extracted Data to CSV
        csv_writer.writerow([
            match_offset, entry_type, private_browsing_id, 
            first_party_domain, requested_resource
        ])

def extract_socks5_traffic(dump_file_path, output_csv_path):
    """Reads the entire file using mmap and processes matches sequentially."""
    start_time = time.time()
    print(f"Processing started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n")

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Offset", "Type", "Private Browsing ID", "First Party Domain", "Request"])

        with open(dump_file_path, 'rb') as dump_file:
            with mmap.mmap(dump_file.fileno(), 0, access=mmap.ACCESS_READ) as memory_data:
                match_offsets = sorted(match.start() for match in pattern_re.finditer(memory_data))

                for offset in match_offsets:
                    process_match(offset, memory_data, csv_writer)

    end_time = time.time()
    print(f"\nProcessing completed at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
    elapsed_time = end_time - start_time
    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f"Total execution time: {int(hours):02d}:{int(minutes):02d}:{seconds:.2f}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract Tor Browser Requests from Memory.')
    parser.add_argument('-i', '--input', type=str, required=True, help='Path to the memory dump file.')
    parser.add_argument('-o', '--output', type=str, required=True, help='Path to the output CSV file.')

    args = parser.parse_args()
    print(banner("Browser Requests"))

    if not os.path.isfile(args.input):
        print("The specified memory dump file does not exist.")
    else:
        extract_socks5_traffic(args.input, args.output)
