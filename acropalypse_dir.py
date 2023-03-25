# Based on https://github.com/infobyte/CVE-2023-21036
# Based on https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02

import zlib
import time
import sys
import os
import fnmatch

start_time = time.time()
vulnCount = 0

if len(sys.argv) != 2:
  print(f"USAGE: {sys.argv[0]} /path/to/directory_of_png_or_jpg_images/")
  exit()

directory_path = sys.argv[1]

# Check if the directory exists
if not os.path.isdir(directory_path):
  print(f"Error: {directory_path} is not a valid directory")
  sys.exit(1)

def get_recursive_file_list(directory):
  file_list = []
  for root, _, files in os.walk(directory):
    for file in files:
      _, file_extension = os.path.splitext(file)
      if file_extension.lower() == '.png' or file_extension.lower() == '.jpg' or file_extension.lower() == 'jpeg':
        file_list.append(os.path.join(root, file))
  return file_list

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

def parse_png_chunk(stream):
  size = int.from_bytes(stream.read(4), "big")
  ctype = stream.read(4)
  body = stream.read(size)
  csum = int.from_bytes(stream.read(4), "big")
  assert(zlib.crc32(ctype + body) == csum)
  return ctype, body

def valid_png_iend(trailer):
  iend_pos = len(trailer) - 8
  iend_size = int.from_bytes(trailer[iend_pos-4:iend_pos], "big")
  iend_csum = int.from_bytes(trailer[iend_pos+4:iend_pos+8], "big")
  return iend_size == 0 and iend_csum == 0xAE426082

def parse_png(f_in):
  magic = f_in.read(len(PNG_MAGIC))
  assert(magic == PNG_MAGIC)
  # find end of cropped PNG
  while True:
    ctype, body = parse_png_chunk(f_in)
    if ctype == b"IEND":
      break

  # grab the trailing data
  trailer = f_in.read()

  if trailer and valid_png_iend(trailer):
    print(f"Potentially vulnerable: {f_in.name}")
    return True
  return False


def parse_jpeg(f_in):
  SOI_marker = f_in.read(2)
  assert(SOI_marker == b"\xFF\xD8")
  APP0_marker = f_in.read(2)
  assert(APP0_marker == b"\xFF\xE0")
  APP0_size = int.from_bytes(f_in.read(2), "big")
  APP0_body = f_in.read(APP0_size - 2)
  assert(APP0_body[:4] == b"JFIF")
  
  f_in.seek(0,0)
  file = f_in.read()
  EOI_marker_pos = file.index(b"\xFF\xD9")

  assert(EOI_marker_pos)
  
  cropped = file[:EOI_marker_pos + 2]
  trailer = file[EOI_marker_pos + 2:]

  if trailer and trailer[-2:] == b"\xFF\xD9":
    print(f"Potentially vulnerable: {f_in.name}")
    return True
  return False

images_to_check = get_recursive_file_list(directory_path)

if images_to_check:
  for image in images_to_check:
    f_in = open(image, "rb")
    start = f_in.read(2)
    f_in.seek(0,0)

    if start == b"\x89P":
      try:
        is_vulnerable = parse_png(f_in)
        if is_vulnerable:
          vulnCount += 1
      except:
        continue
    elif start == b"\xFF\xD8":
      try:
        is_vulnerable = parse_jpeg(f_in)
        if is_vulnerable:
          vulnCount += 1
      except:
        continue
    else:
      print("File doesn't appear to be jpeg or png.")
else:
  print("No images to check; quitting.")
  sys.exit(1)

elapsed_time = time.time() - start_time
print(f"Found {vulnCount} vulnerable images out of a scanned total of {len(images_to_check)}.")
print(f"Total time to execute: {elapsed_time:2f} seconds")