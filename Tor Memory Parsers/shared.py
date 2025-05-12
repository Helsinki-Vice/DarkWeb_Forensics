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