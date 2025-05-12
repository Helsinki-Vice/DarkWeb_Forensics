import mmap
import re

from shared import run_argparser

# Pre-compile the pattern for efficiency
patterns = [
    b'\xFF\xFF\x72\x65\x71\x75\x65\x73\x74\x49\x64'
]
pattern_re = re.compile(b'|'.join(re.escape(p) for p in patterns))

def process_match(match_offset: int, memory_data: mmap.mmap, csv_writer, _: str | None):
    """Manually walks the memory data to extract HTTP request metadata"""
    try:
        matched_prefix = memory_data[match_offset:match_offset + 26]
    except IndexError:
        return  

    index = match_offset + 26 


    request_id = "Unknown"
    url = "Unknown"
    origin_url = "Unknown"
    document_url = "Unknown"
    method = "Unknown"
    request_type = "Unknown"

    # Extract Request ID
    try:
        request_id = memory_data[index:index+8].decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        request_id = "Decoding Error"
    index += 8 

    # Extract URL 
    url_marker = memory_data.find(b'\xFF\xFF', index, index + 8)
    if url_marker != -1 and memory_data[url_marker + 2:url_marker + 5] == b'url':
        url_start = memory_data.find(b'\xFF\xFF', url_marker + 5, url_marker + 20)
        if url_start != -1:
            index = url_start + 2
            url_end = memory_data.find(b'\x00\x00', index, index + 2000)
            if url_end != -1:
                try:
                    url = memory_data[index:url_end].decode(errors='ignore').strip()
                except UnicodeDecodeError:
                    url = "Decoding Error"
                index = url_end + 2  

    # Extract Origin URL 
    originURL_marker = memory_data.find(b'\xFF\xFF', index, index + 50)
    if originURL_marker != -1 and memory_data[originURL_marker + 2:originURL_marker + 11] == b'originUrl':
        originURL_start = memory_data.find(b'\xFF\xFF', originURL_marker + 12, originURL_marker + 62)
        if originURL_start != -1:
            index = originURL_start + 2
            originURL_end = memory_data.find(b'\x00\x00', index, index + 2000)
            if originURL_end != -1:
                try:
                    origin_url = memory_data[index:originURL_end].decode(errors='ignore').strip()
                except UnicodeDecodeError:
                    origin_url = "Decoding Error"
                index = originURL_end + 2

    # Extract Document URL
    documentURL_marker = memory_data.find(b'\xFF\xFF', index, index + 50)
    if documentURL_marker != -1 and memory_data[documentURL_marker + 2:documentURL_marker + 13] == b'documentUrl':
        documentURL_start = memory_data.find(b'\xFF\xFF', documentURL_marker + 12, documentURL_marker + 62)
        if documentURL_start != -1:
            index = documentURL_start + 2
            documentURL_end = memory_data.find(b'\x00\x00', index, index + 2000)
            if documentURL_end != -1:
                try:
                    document_url = memory_data[index:documentURL_end].decode(errors='ignore').strip()
                except UnicodeDecodeError:
                    document_url = "Decoding Error"
                index = documentURL_end + 2  

    # Extract Method 
    method_marker = memory_data.find(b'\xFF\xFF', index, index + 50)
    if method_marker != -1 and memory_data[method_marker + 2:method_marker + 8] == b'method':
        method_start = memory_data.find(b'\xFF\xFF', method_marker + 8, method_marker + 58)
        if method_start != -1:
            index = method_start + 2
            method_end = memory_data.find(b'\x00\x00', index, index + 2000)
            if method_end != -1:
                try:
                    method = memory_data[index:method_end].decode(errors='ignore').strip()
                except UnicodeDecodeError:
                    method = "Decoding Error"
                index = method_end + 2  

    # Extract Type 
    type_marker = memory_data.find(b'\xFF\xFF', index, index + 50)
    if type_marker != -1 and memory_data[type_marker + 2:type_marker + 6] == b'type':
        type_start = memory_data.find(b'\xFF\xFF', type_marker + 6, type_marker + 56)
        if type_start != -1:
            index = type_start + 2
            type_end = memory_data.find(b'\x00\x00', index, index + 2000)
            if type_end != -1:
                try:
                    request_type = memory_data[index:type_end].decode(errors='ignore').strip()
                except UnicodeDecodeError:
                    request_type = "Decoding Error"
                index = type_end + 2  
                

    print(f"[+] Extracted URL Information from HTTP Request at offset {match_offset}")

    # Write extracted data to CSV
    csv_writer.writerow([
        match_offset, "HTTP Request", method, request_id, url, origin_url, document_url, request_type, 
    ])

if __name__ == '__main__':
    run_argparser(
        description = "Extract URL information from HTTP Requests from a Memory Dump",
        input_help = "Path to the memory dump file.",
        output_help = "Path to the output CSV file.",
        program_name = "HTTP Requests",
        csv_headers = ["Offset", "Type", "Method", "Request ID", "URL", "Origin URL", "Document URL", "Resource Type"],
        regex_pattern = pattern_re,
        process_matcher = process_match,
        output_folder = ""
    )
