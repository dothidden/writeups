---
title: "Hidden Wave"
date: 2023-05-24T21:53:09+03:00
tags:
- forensics
- steganography
- audio
---

The file looked perfectly normal and sounded perfectly normal. Extracting the
LSB is quite a common technique to try and was fortunately successful.

```python
# Use wave package (native to Python) for reading the received audio file
import wave
# Read file as binary stream do not forget to change the file name
song = wave.open("hidden-wave.wav", mode='rb')
# Convert audio to byte array
frame_bytes = bytearray(list(song.readframes(song.getnframes())))

# Extract the LSB of each byte
extracted = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
# Convert byte array back to string
string = "".join(chr(int("".join(map(str,extracted[i:i+8])),2)) for i in range(0,len(extracted),8))
# Cut off at the filler characters
decoded = string.split("###")[0]

# Print the extracted text
print(f"Sucessfully decoded: {decoded}")
song.close()
```

### Decoded Flag
`CTF{UNZSFEFEWF@SDF-NOICE}`
