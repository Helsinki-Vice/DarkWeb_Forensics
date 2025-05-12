import mmap
import re

from shared import run_argparser
from records import BrowserActivity

# Pre-compile patterns for efficiency
patterns = [
    b'\x01\x00\x00\x00\xF8\x00\x00\x00',
    b'\x01\x00\x00\x00\xF8\x01\x00\x00',
    b'\x01\x00\x00\x00\xF8\x03\x00\x00',    
    b'\x02\x00\x00\x00\xF8\x01\x00\x00', 
    b'\x02\x00\x00\x00\xF8\x00\x00\x00',
    b'\x02\x00\x00\x00\xF8\x03\x00\x00',    
    b'\x03\x00\x00\x00\xF8\x01\x00\x00', 
    b'\x03\x00\x00\x00\xF8\x00\x00\x00',
    b'\x04\x00\x00\x00\xF8\x00\x00\x00',
    b'\x05\x00\x00\x00\xF8\x00\x00\x00',
]
pattern_re = re.compile(b'|'.join(re.escape(p) for p in patterns))  # Join patterns into one regex

def process_match(match_offset: int, memory_data: mmap.mmap, output_folder: str | None) -> BrowserActivity | None:
    """Processes pattern match within memory dump and writes relevant data to CSV."""
    match_prefix_len = 8
    try:
        matched_prefix = memory_data[match_offset:match_offset + match_prefix_len]
    except IndexError:
        return  

    index = match_offset + match_prefix_len

    if matched_prefix:
        extracted_data = ""  
        entry_type = "Potential Browser Activity"

        first_byte = memory_data[index:index+1]
        utf16_attempt = False  

        if first_byte not in (b'\x00', b'\x08', b'\xFF', b'\xD0', b'\x2E', b'\x4F'):
            http_data_start = index
            termination_pattern = re.compile(rb'\x00\x0E|\x00\xE5|\x00\x00')
            match = termination_pattern.search(memory_data[http_data_start:])
            if not match:
                return None
            http_data_end = http_data_start + match.start()

            try:
                extracted_data = ''.join(
                    c for c in memory_data[http_data_start:http_data_end].decode('utf-8', errors='ignore').strip()
                    if c.isprintable()
                )
            except UnicodeDecodeError:
                try:
                    extracted_data = ''.join(
                        c for c in memory_data[http_data_start:http_data_end].decode('utf-16', errors='ignore').replace(' ', '').strip()
                        if c.isprintable()
                    )
                    utf16_attempt = True
                except UnicodeDecodeError:
                    extracted_data = f"[Non-printable: {memory_data[http_data_start:http_data_end].hex()}]"

            # Skip writing if no printable data is found**
            if not extracted_data.strip():
                return None

            index = http_data_end + 2  
            print(f"[+] Potential Browser Activity identified at offset: {index}")

            return BrowserActivity(match_offset, entry_type, extracted_data)

if __name__ == '__main__':
    run_argparser(
        description = "Extract Potential Tor Browser activity from Memory.",
        input_help = "Path to the memory dump file.",
        output_help = "Path to the output CSV file.",
        program_name = "Potential Browser Activity",
        csv_headers = ["Offset", "Type", "Extracted Data"],
        regex_pattern = pattern_re,
        process_matcher = process_match,
        output_folder = ""
    )