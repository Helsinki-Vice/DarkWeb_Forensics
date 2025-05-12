import os
import argparse
import mmap
import re
import time
import csv

from shared import run_argparser

# Pre-compile patterns for efficiency
patterns = [
    b'\x01\x00\x00\x00\xF8\x00\x00\x00\x2E',
    b'\x01\x00\x00\x00\xF8\x01\x00\x00\x2E',   
    b'\x02\x00\x00\x00\xF8\x01\x00\x00\x2E', 
    b'\x02\x00\x00\x00\xF8\x00\x00\x00\x2E',   
]
pattern_re = re.compile(b'|'.join(re.escape(p) for p in patterns))  # Join patterns into one regex

def process_match(match_offset, memory_data, csv_writer):
    """Processes pattern match within memory dump"""
    try:
        matched_prefix = memory_data[match_offset:match_offset + 9]
    except IndexError:
        return  

    index = match_offset + 9 

    if matched_prefix:
        tls_metadata = ""
        url = ""
        socks_info = ""
        second_url = ""
        private_browsing_id = ""
        first_party_domain = ""

        def stop_extraction():
            print (f"[+] Partially Carved SOCKS5 Traffic Identified at offset {match_offset}")
            return match_offset, "Partially Carved SOCKS5 Browser Request", tls_metadata, url, socks_info, second_url, private_browsing_id, first_party_domain

        # Extract TLS metadata (Required)
        tls_metadata_start = memory_data.find(b'[tlsflags', index)
        if tls_metadata_start != -1 and tls_metadata_start <= match_offset + 50:
            tls_metadata_end = memory_data.find(b']', tls_metadata_start)
            if tls_metadata_end != -1:
                tls_metadata = memory_data[tls_metadata_start:tls_metadata_end+1].decode(errors='ignore').strip()
                tls_metadata = tls_metadata.replace("[tlsflags", "").replace("]", "").strip()
                index = tls_metadata_end + 1

        # Extract Requested URL (Required)
        url_start = index
        url_end = memory_data.find(b'(socks', index)
        if url_end != -1:
            url = memory_data[url_start:url_end].decode(errors='ignore').strip()
            index = url_end + len(b'(socks:') 
       
       # Ensure Required Fields Are Present
        if tls_metadata == "" or url == "":
            return  # Skip incomplete entries if any required field is missing
        
        # Extract SOCKS info
        socks_info_end = memory_data.find(b')', index)
        if socks_info_end != -1:
            if socks_info_end - index > 20:
                csv_writer.writerow(stop_extraction())
                return
            socks_info = memory_data[index:socks_info_end].decode(errors='ignore').strip()
            index = socks_info_end + 1  # Move past closing bracket


        # Extract Second URL
        second_url_start = memory_data.find(b'[', index)
        if second_url_start != -1:
            second_url_start += 1  
            second_url_end = memory_data.find(b':0:', second_url_start)
            if second_url_end != -1 and second_url_end <= index + 65:
                second_url = memory_data[second_url_start:second_url_end].decode(errors='ignore').strip()
                index = second_url_end + 3  
            else:
                csv_writer.writerow(stop_extraction())
                return  

        # Extract Private Browsing ID 
        private_start = memory_data.find(b'privateBrowsingId=', index)
        if private_start != -1 and private_start <= index + 200:
            private_id_start = private_start + len(b'privateBrowsingId=')
            private_browsing_id_byte = memory_data[private_id_start:private_id_start+1]
            try:
                private_browsing_id = private_browsing_id_byte.decode('utf-8')
                if not private_browsing_id.isprintable():
                    private_browsing_id = f"[Non-printable: {private_browsing_id_byte.hex()}]"
            except UnicodeDecodeError:
                private_browsing_id = f"[Non-printable: {private_browsing_id_byte.hex()}]"
            index = private_id_start + 1
        else:
            csv_writer.writerow(stop_extraction())
            return  

        # Extract First Party Domain 
        first_party_start = memory_data.find(b'firstPartyDomain=', index)
        if first_party_start != -1:
            first_party_start += len(b'firstPartyDomain=')
            first_party_end = memory_data.find(b'\x00', first_party_start)
            if first_party_end != -1:
                first_party_domain = memory_data[first_party_start:first_party_end].decode(errors='ignore').strip()
                index = first_party_end + 1  
            else:
                csv_writer.writerow(stop_extraction())
                return  

        print(f"[+] SOCKS5 Traffic Identified at offset {match_offset}")

        # **Write Extracted Data to CSV**
        csv_writer.writerow([
            match_offset, "SOCKS5 Browser Request", tls_metadata, url, 
            socks_info, second_url, private_browsing_id, first_party_domain
        ])

def extract_socks5_traffic(dump_file_path, output_csv_path):
    """Reads the entire file using mmap"""
    start_time = time.time()
    print(f"Processing started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n")

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([
            "Offset", "Type", "TLS Flags", "Requested Connection",
            "SOCKS Info", "Session Connection", "Private Browsing ID", "First Party Domain"
        ])

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
    run_argparser(
        description = "Extract Tor SOCKS5 Requests from a Memory Dump",
        input_help = "Path to the memory dump file.",
        output_help = "Path to the output CSV file.",
        program_name = "SOCKS5 Requests",
        program = extract_socks5_traffic
    )
