import mmap
import re

from shared import run_argparser
from base64icon import extract_base64_icon
from records import TabData

# Pre-compile the pattern for efficiency
patterns = [
    b'\xFF\xFF\x66\x69\x72\x65\x66\x6F\x78\x2D\x70\x72\x69\x76\x61\x74\x65\x00'
]
pattern_re = re.compile(b'|'.join(re.escape(p) for p in patterns))

def process_match(match_offset: int, memory_data: mmap.mmap, extracted_icons_folder: str | None) -> TabData | None:
    """Manually walks the memory data to extract Browser Tab Session Data."""
    match_prefix_len = 26
    try:
        matched_prefix = memory_data[match_offset:match_offset + match_prefix_len]
    except IndexError:
        return  

    index = match_offset + match_prefix_len  # Move past matched pattern

    # Locate 'url'
    url_marker = memory_data.find(b'url', index, index + 15)
    if url_marker == -1:  
        return  # Skip if 'url' is not found

    index = url_marker + 3 

    # Initialize extracted fields
    url = ""
    title = "Title Not Present"
    favicon_url = "FavIconURL Not Present"

    # Extract URL
    url_start_marker = memory_data.find(b'\xFF\xFF', index, index + 16)
    if url_start_marker != -1:
        index = url_start_marker + 2 
        url_end = memory_data.find(b'\x00\x00', index, index + 2000)
        if url_end != -1:
            try:
                url = memory_data[index:url_end].decode(errors='ignore').strip()
            except UnicodeDecodeError:
                url = "Decoding Error"
            index = url_end + 2 

    # Extract Title
    title_marker = memory_data.find(b'title', index, index + 50)
    if title_marker != -1:
        index = title_marker + 5
        title_start_marker = memory_data.find(b'\xFF\xFF', index, index + 16)  # Find FF FF within 16 bytes
        if title_start_marker != -1:
            index = title_start_marker + 2 
            title_end = memory_data.find(b'\x00\x00', index, index + 2000)  # End marker for Title
            if title_end != -1:
                try:
                    title = memory_data[index:title_end].decode(errors="ignore").strip()
                except UnicodeDecodeError:
                    title = "Decoding Error"
                index = title_end + 2 

    # Extract FavIconURL
    favicon_marker = memory_data.find(b'favIconUrl', index, index + 50)  # Search for FavIcon URL
    if favicon_marker != -1:
        index = favicon_marker + 10  # Move past 'favIconUrl'
        favicon_start_marker = memory_data.find(b'\xFF\xFF', index, index + 24)  # Search for `FF FF`
        if favicon_start_marker != -1:
            index = favicon_start_marker + 2  # Move past `FF FF`
            
            # Detect encoding (UTF-16 if 2nd byte is 0x00, otherwise assume UTF-8)
            is_utf16 = memory_data[index + 1] == 0x00  

            # Find the end of the URL dynamically
            favicon_end = index
            if is_utf16:
                # UTF-16: Stop at first odd-byte that is NOT `0x00`
                while favicon_end + 1 < len(memory_data):
                    if favicon_end % 2 != 0 and memory_data[favicon_end] != 0x00:  
                        break
                    favicon_end += 1
            else:
                # UTF-8: Stop at first non-printable character
                while favicon_end < len(memory_data):
                    if memory_data[favicon_end] < 0x20:  # Stop at first non-printable byte
                        break
                    favicon_end += 1

            # Extract and decode the favicon URL**
            if favicon_end > index:
                try:
                    raw_favicon_bytes = memory_data[index:favicon_end]
                    
                    # Decode based on detected encoding
                    if is_utf16:
                        favicon_url = raw_favicon_bytes.decode("utf-16-le", errors="ignore").strip()
                    else:
                        favicon_url = raw_favicon_bytes.decode("utf-8", errors="ignore").strip()

                except UnicodeDecodeError:
                    favicon_url = "Decoding Error"

                index = favicon_end  # Move index past extracted data

                # Check if the extracted URL is Base64 and extract the icon
                if extracted_icons_folder:
                    extract_base64_icon(favicon_url, match_offset, extracted_icons_folder)
                
    print(f"[+] Extracted Browser Tab Session Data at offset {match_offset}")

    # Write extracted data to CSV
    return TabData(match_offset, "Browser Tab Session Data", url, title, favicon_url)

if __name__ == '__main__':
    run_argparser(
        description = "Extract Browser Tab Session Data from a Memory Dump",
        input_help = "Path to the memory dump file.",
        output_help = "Path to the output folder.",
        program_name = "Browser Tab Session Data",
        csv_headers = ["Offset", "Type", "URL", "Title", "FavIcon URL"],
        regex_pattern = pattern_re,
        process_matcher = process_match,
        output_folder = ""
    )