import mmap
import re

from shared import run_argparser
from records import BrowserRequest

# Pre-compile patterns for efficiency
patterns = [
    b'\x02\x00\x00\x00\xF8\x01\x00\x00\x4F\x5E',
    b'\x02\x00\x00\x00\xF8\x00\x00\x00\x4F\x5E',
    b'\x02\x00\x00\x00\xF8\x03\x00\x00\x4F\x5E',
]
pattern_re = re.compile(b'|'.join(re.escape(p) for p in patterns))  # Join patterns into one regex

def process_match(match_offset: int, memory_data: mmap.mmap, _: str | None) -> BrowserRequest | None:
    """Processes pattern match within memory dump and writes to CSV only if required fields exist."""
    match_prefix_len = 9
    try:
        matched_prefix = memory_data[match_offset:match_offset + match_prefix_len]
    except IndexError:
        return  

    index = match_offset + match_prefix_len

    if matched_prefix:
        private_browsing_id = ""
        first_party_domain = ""
        requested_resource = ""  
        entry_type = "Browser Request" 

        # Extract Private Browsing ID (Required)
        private_start = memory_data.find(b'privateBrowsingId=', index)
        if private_start == -1 or private_start > index + 100:
            return None

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

        return BrowserRequest(match_offset, entry_type, private_browsing_id, first_party_domain, requested_resource)

if __name__ == '__main__':
    run_argparser(
        description = "Extract Tor Browser Requests from Memory.",
        input_help = "Path to the memory dump file.",
        output_help = "Path to the output CSV file.",
        program_name = "Browser Requests",
        csv_headers = ["Offset", "Type", "Private Browsing ID", "First Party Domain", "Request"],
        regex_pattern = pattern_re,
        process_matcher = process_match,
        output_folder = ""
    )