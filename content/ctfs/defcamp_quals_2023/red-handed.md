---
title: Red-Handed
type: writeup
date: 2023-10-22T15:29:17-04:00
description: Writeup for Red-Handed [Defcamp Quals 2023]
author: Koyossu
tags:
- network
draft: false
---
___

## Challenge Description

Someone has connected to my network and its trying to hack me.

Find the flag. Flag format CTF{sha256}

By far the most fun challange in the competition. You received a pcap capture and had to go down the rabbit hole.

## Intuition

Opening the pcap we can observe that the communication is bluetooth. We than kept grinding and understanding the communication protocol and we were able to subsctract some conclusions. There is a bluetooth communication between 2 devices and one is trying to send a png file to the other device.

![img.png](/images/defcamp_quals_2023/rh1.png)

Upon applying some filters to the communication we can better see that there were 4 attempts in total to send a png file. The last one being successful. Also in the first frame of the png payload there are some bytes that spell flag.png. Surely this is the right track.

Filters used: 
`bthci_acl.dst.bd_addr == 5c:17:cf:0e:81:5a || bthci_acl.src.bd_addr == 5c:17:cf:0e:81:5a`
`bthci_acl.dst.bd_addr == 5c:17:cf:0e:81:5a && frame contains IHDR` or `bthci_acl.dst.bd_addr == 5c:17:cf:0e:81:5a && frame contains IEND`
![img.png](/images/defcamp_quals_2023/rh2.png)

![img.png](/images/defcamp_quals_2023/rh3.png)

## Solution

So what we thought is to extract the specific frames that have the data of the picture. This is the fourth attempt that the device had to send the png. There were in total 29 frames. We extracted all of them into binary files using Ctrl + Shift + X from Wireshark.

Now that we have the data we need to extract only the payload data from the frame. Upon reading the documentation and carefully inspecting the frames we see that for the Start Communication frames we have 13 bytes of encapsulation data, headers and so on, and 2 bytes at the end of the payload that are the frame check sequences.

Doing this we just then put everything together into a file using HxD concatenation feature and delete extra bytes from the new file so that the file started with the png magic bytes so it can be properly displayed

![img.png](/images/defcamp_quals_2023/rh4.png)


![img.png](/images/defcamp_quals_2023/rh5.png)

Looking at the image we see this result 


We are on the right track but for some reason the image didn't render correctly. We go back to the roots in wireshark and we observe that the frame payload is actually an encapsulated OBEX object. Upon further reading the documentation of OBEX object push and response we now know that the frame payload had 6 extra bytes that needed to be deleted from every Start communication frame. 

![img.png](/images/defcamp_quals_2023/rh7.png)


At the end we reached this script that removed all the extra bytes and we repeated the process of concatenating the results in HxD, removing at the end the extra bytes. 

```sh
# Loop from p1 to p29
for i in {1..29}; do
    # Define the input and output files based on the loop counter
    input_file="p${i}"
    output_file="p${i}.bin"

    # Check if the input file exists before processing
    if [[ -f "$input_file" ]]; then
        # Determine the offset based on the value of i
        if [[ "$i" == 1 ]]; then
            offset=13
        elif [[ "$i" == 10 || "$i" == 19 || "$i" == 28 ]]; then
            offset=$((13+6))
        else
            offset=11
        fi
        
        # Skip the offset bytes using dd
        dd if="$input_file" of="$output_file" bs=1 skip=$offset

        # Remove the last 2 bytes from the output file
        truncate -s -2 "$output_file"

        echo "Processed $input_file to $output_file"
    else
        echo "File $input_file does not exist. Skipping."
    fi
done

echo "Operation completed."
```

TADA ! 

![img.png](/images/defcamp_quals_2023/rh6.png)


### Flag
Here is the final flag, and a proof from the website :)

![img.png](/images/defcamp_quals_2023/rhFlag.png)

`CTF{ad6f194e96b6538168c95423b234cc0604e716d22287e16554f43d4a3e8fb989}`
