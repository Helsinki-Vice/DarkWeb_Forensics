import os
import argparse
import mmap
import re
import time
import csv
import base64

# Pre-compile the pattern for efficiency
patterns = [
    b'\xFF\xFF\x66\x69\x72\x65\x66\x6F\x78\x2D\x70\x72\x69\x76\x61\x74\x65\x00'
]
pattern_re = re.compile(b'|'.join(re.escape(p) for p in patterns))


def is_valid_base64(s):
    """Check if a string is a valid Base64 encoded string."""
    try:
        base64.b64decode(s, validate=True)
        return True
    except (base64.binascii.Error, ValueError):
        return False


def extract_base64_icon(favicon_url, index, extracted_icons_folder):
    """Extract base64-encoded favicons and save them to a folder."""
    
    if not favicon_url.startswith('data:image'):
        return None  # Not a Base64 image

    try:
        # Extract Base64 data part
        base64_data = favicon_url.split(',', 1)[1].strip()

        # Ensure only valid Base64 characters remain
        base64_data = re.sub(r'[^A-Za-z0-9+/=]', '', base64_data)

        # Validate Base64 data before decoding
        if not is_valid_base64(base64_data):
            print(f"[-] Invalid Base64 favicon at offset {index}, skipping extraction.")
            return None

        # Decode Base64 data
        image_data = base64.b64decode(base64_data)

        # Determine file extension
        file_extension = 'ico' if 'image/x-icon' in favicon_url else 'png'

        # Ensure output folder exists
        os.makedirs(extracted_icons_folder, exist_ok=True)

        # Name the file as the starting offset for the favicon data
        output_filename = f"{index}_favicon.{file_extension}"
        icon_output = os.path.join(extracted_icons_folder, output_filename)

        # Save image data to file
        with open(icon_output, 'wb') as image_file:
            image_file.write(image_data)

        print(f"[+] Favicon Extracted: {icon_output}")
        return output_filename, icon_output

    except (base64.binascii.Error, OSError, IndexError, ValueError) as e:
        print(f"[-] Error decoding Base64 Favicon at offset {index}: {e}")
        return None

def process_match(match_offset, memory_data, csv_writer, extracted_icons_folder):
    """Manually walks the memory data to extract Browser Tab Session Data."""
    try:
        matched_prefix = memory_data[match_offset:match_offset + 26]
    except IndexError:
        return  

    index = match_offset + 26  # Move past matched pattern

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
                extract_base64_icon(favicon_url, match_offset, extracted_icons_folder)
                
    print(f"[+] Extracted Browser Tab Session Data at offset {match_offset}")

    # Write extracted data to CSV
    csv_writer.writerow([
        match_offset, "Browser Tab Session Data", url, title, favicon_url
    ])


def extract_tabdata(dump_file_path, output_folder):
    """Reads the memory dump and extracts Browser Tab Session Data."""
    start_time = time.time()
    print(f"Processing started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n")
    
    # Create the main output folder based on user input
    os.makedirs(output_folder, exist_ok=True)

    # Define CSV file path inside the output folder
    output_csv_path = os.path.join(output_folder, f"{os.path.basename(output_folder)}.csv")

    # Create Favicon output folder inside the main output folder
    extracted_icons_folder = os.path.join(output_folder, "Extracted FavIcons")
    os.makedirs(extracted_icons_folder, exist_ok=True)

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Offset", "Type", "URL", "Title", "FavIcon URL"])

        with open(dump_file_path, 'rb') as dump_file:
            with mmap.mmap(dump_file.fileno(), 0, access=mmap.ACCESS_READ) as memory_data:
                match_offsets = sorted(match.start() for match in pattern_re.finditer(memory_data))

                for offset in match_offsets:
                    process_match(offset, memory_data, csv_writer, extracted_icons_folder)
    end_time = time.time()
    print(f"\nProcessing completed at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
    elapsed_time = end_time - start_time
    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f"Total execution time: {int(hours):02d}:{int(minutes):02d}:{seconds:.2f}")

    print(f"\nResults saved to: {output_csv_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract Browser Tab Session Data from a Memory Dump')
    parser.add_argument('-i', '--input', type=str, required=True, help='Path to the memory dump file.')
    parser.add_argument('-o', '--output', type=str, required=True, help='Path to the output folder.')

    args = parser.parse_args()
    
    print(r"""
   _____                 _             ______                       _          
  / ____|               | |           |  ____|                     (_)         
 | (___  _ __  _   _  __| | ___ _ __  | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
  \___ \| '_ \| | | |/ _` |/ _ \ '__| |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
  ____) | |_) | |_| | (_| |  __/ |    | | | (_) | | |  __/ | | \__ \ | (__\__ \
 |_____/| .__/ \__, |\__,_|\___|_|    |_|  \___/|_|  \___|_| |_|___/_|\___|___/
        | |     __/ |                                                          
        |_|    |___/    

Tor Browser Memory Parser - Browser Tab Session Data
Version: 1.0 Feb, 2025
Author: Spyder Forensics Training
Website: www.spyderforensics.com
Course: Host-Based Dark Web Forensics
""")

    extract_tabdata(args.input, args.output)
