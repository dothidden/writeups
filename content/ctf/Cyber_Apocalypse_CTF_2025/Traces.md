---
title: Traces
date: 2025-03-27T16:12:33+03:00
description: Writeup for Traces [HTB Cyber Apocalypse CTF 2025]
type: writeup
author: h3pha
tags:
- crypto
draft: false
---
___

## Challenge Description

> Long ago, a sacred message was sealed away, its meaning obscured by the overlapping echoes of its own magic. The careless work of an enchanter has left behind a flaw—a weakness hidden within repetition. With keen eyes and sharper wits, can you untangle the whispers of the past and restore the lost words?

## Intuition

We are provided with this python file (`server.py`):

```python
from db import *
from Crypto.Util import Counter
from Crypto.Cipher import AES
import os
from time import sleep
from datetime import datetime

def err(msg):
    print('\033[91m'+msg+'\033[0m')

def bold(msg):
    print('\033[1m'+msg+'\033[0m')

def ok(msg):
    print('\033[94m'+msg+'\033[0m')

def warn(msg):
    print('\033[93m'+msg+'\033[0m')

def menu():
    print()
    bold('*'*99)
    bold(f"*                                🏰 Welcome to EldoriaNet v0.1! 🏰                                *")
    bold(f"*            A mystical gateway built upon the foundations of the original IRC protocol 📜        *")
    bold(f"*          Every message is sealed with arcane wards and protected by powerful encryption 🔐      *")
    bold('*'*99)
    print()

class MiniIRCServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.key = os.urandom(32)

    def display_help(self):
        print()
        print('AVAILABLE COMMANDS:\n')
        bold('- HELP')
        print('\tDisplay this help menu.')
        bold('- JOIN #<channel> <key>')
        print('\tConnect to channel #<channel> with the optional key <key>.')
        bold('- LIST')
        print('\tDisplay a list of all the channels in this server.')
        bold('- NAMES #<channel>')
        print('\tDisplay a list of all the members of the channel #<channel>.')
        bold('- QUIT')
        print('\tDisconnect from the current server.')

    def output_message(self, msg):
        enc_body = self.encrypt(msg.encode()).hex()
        print(enc_body, flush=True)
        sleep(0.001)

    def encrypt(self, msg):
        encrypted_message = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(msg)
        return encrypted_message
    
    def decrypt(self, ct):
        return self.encrypt(ct)
    
    def list_channels(self):
        bold(f'\n{"*"*10} LIST OF AVAILABLE CHANNELS {"*"*10}\n')
        for i, channel in enumerate(CHANNELS.keys()):
            ok(f'{i+1}. #{channel}')
        bold('\n'+'*'*48)

    def list_channel_members(self, args):
        channel = args[1] if len(args) == 2 else None

        if channel not in CHANNEL_NAMES:
            err(f':{self.host} 403 guest {channel} :No such channel')
            return
        
        is_private = CHANNELS[channel[1:]]['requires_key']
        if is_private:
            err(f':{self.host} 401 guest {channel} :Unauthorized! This is a private channel.')
            return

        bold(f'\n{"*"*10} LIST OF MEMBERS IN {channel} {"*"*10}\n')
        members = CHANNEL_NAMES[channel]
        for i, nickname in enumerate(members):
            print(f'{i+1}. {nickname}')
        bold('\n'+'*'*48)

    def join_channel(self, args):
        channel = args[1] if len(args) > 1 else None
        
        if channel not in CHANNEL_NAMES:
            err(f':{self.host} 403 guest {channel} :No such channel')
            return

        key = args[2] if len(args) > 2 else None

        channel = channel[1:]
        requires_key = CHANNELS[channel]['requires_key']
        channel_key = CHANNELS[channel]['key']

        if (not key and requires_key) or (channel_key and key != channel_key):
            err(f':{self.host} 475 guest {channel} :Cannot join channel (+k) - bad key')
            return
        
        for message in MESSAGES[channel]:
            timestamp = message['timestamp']
            sender = message['sender']
            print(f'{timestamp} <{sender}> : ', end='')
            self.output_message(message['body'])
        
        while True:
            warn('You must set your channel nickname in your first message at any channel. Format: "!nick <nickname>"')
            inp = input('guest > ').split()
            if inp[0] == '!nick' and inp[1]:
                break

        channel_nickname = inp[1]
        while True:
            timestamp = datetime.now().strftime('%H:%M')
            msg = input(f'{timestamp} <{channel_nickname}> : ')
            if msg == '!leave':
                break

    def process_input(self, inp):
        args = inp.split()
        cmd = args[0].upper() if args else None

        if cmd == 'JOIN':
            self.join_channel(args)
        elif cmd == 'LIST':
            self.list_channels()
        elif cmd == 'NAMES':
            self.list_channel_members(args)
        elif cmd == 'HELP':
            self.display_help()
        elif cmd == 'QUIT':
            ok('[!] Thanks for using MiniIRC.')
            return True
        else:
            err('[-] Unknown command.')


server = MiniIRCServer('irc.hackthebox.eu', 31337)

exit_ = False
while not exit_:
    menu()
    inp = input('> ')
    exit_ = server.process_input(inp)
    if exit_:
        break
```

After playing with it offline to see how it works. I started the instance and found 2 channels: `#general` and `#secret`. I could not enter `#secret` because I do not have the key, duuh, but this was the conversation from the `#general` channel:

```
[23:30] <Doomfang> : e243ed3a56be2422da937881b3da
[23:32] <Stormbane> : e243ed3a56be3339da8c7382bcd3f1
[23:34] <Runeblight> : e243ed3a56be3238db9b7c8cb4dafc74
[00:00] <Stormbane> : 9448a32f58be0722c1de7fc0b3d8e3203ecfd9869fad04b4247f7c1f50a1e03495faf502d2870389f60f6924b4b935122d46882211a042b188202a4b11f007e17cb1
[00:01] <Doomfang> : 9643e03c4fed1422da9a30c095dce7203ececcd49bef09a4353128165bf8b2229ef8f75193c16f98ea4d7724adb93710625c8d395fa40aa3956e395c58e913e739f33a8b2ef36e7dd1143e
[00:02] <Runeblight> : 8d42f07944fb1461959c6b94fdf4b36d6ac5c1c39da402af377f7b1858e4b22499eaea049dcb6f9feb4f7465b3af7e42444fdd2459a653f08f65344a1da613e635bf2c9d7abe6a75cf0521cd8bf6dafbfab5601269f3102441b64d4988760c931542d434945e
[00:04] <Doomfang> : 9745ed2a1dfd082cdb907b8cfdd4e72024c9dd868dae0da47039670515edfd3f90bfed1090cc3cc2a2647f70f8af70117a40893359e35ebfdc6f2f4b58f614fc6ffe2f9d7aa16c7dca5f
[00:04] <Doomfang> : 8b48f63c1df7136dc1967bc0addce7733acedbc78daa4ba73f2d281840f3b22292fcec0399872c84e3467461b3e670476040cf37478b6293aa353c6613e504a843ab2dad16a26c4bed576ef7
[00:05] <Runeblight> : 8442f07954ea4e6dfa907299fdcefc6138c389cf8aef1ca82437281840f3b23c98eced5188d53a9ff64d7e24beb03c0b685ad3
[00:06] <Stormbane> : 9a48f7771dd1153f95927f93a99df96f3cc389cb9fb64ba931296d5759e4f425d7ebeb109fc23cc2a27f7f24b2a923162d4b987047a658a9dc633b4b1de013f937
[00:07] <Doomfang> : 8a0ae9795ef6052ede977087fdd2e1726acac6c18def1fae703d6d5746f4e034d7f1f65188d52e8fe7087562ffb325102d489e2458ac44a3dc723f5419ef08e637
[00:08] <Runeblight> : 8848e1291df3056dc08e7a81a9d8f02e6aefcf868aa70eb8703c690356e9b23e99b3b90699802380a2407b72bafc240d2d489e2411a54ba3882e
[00:09] <Stormbane> : 8a0ae8351dfd0f20c59f6c85fdc9fc656acac8d29bbc1fe1343e7c1615f6fb259fbff6048e872d8de1436f74ffac3c036307dd0754e347a58f747a5c0ae715f039fe35817aa06a75c95176c0caf7daa9ebfa281473f750
[00:10] <Doomfang> : 8a4ba43c4bfb1234c196778eba9dfd736ac5c5c39fbd47e1273a281a5af7f77183f0b90594c26f82e7506e24aca831056807dd1f44b10ab79361361911f546e270eb339134f37177c612698b
[00:11] <Runeblight> : 8b42e83d1df10e6395b7398dfdcef16523c8ce868dbb19a03e386d5746e8f53f96f3ea519ad52081a2476f70acb534072309aa3511ae43b794747a5b1da611f46dfc339d3efd
[00:12] <Stormbane> : 9448a43a5cf04739958a7f8bb89df56e3386dbcf8da418ef70136d0312f2b23d92feef14dcd32785f108796cbeb23e0761099f3557ac58b5dc74325c01a612e778fc30d82fa02d
[00:13] <Doomfang> : 824af63c58fa4e6df8916885fddcf86c6ad2c8ca95bc4bb53f7f7c1f50a1e2239ee9f80599873d83ed4534248da93e076f45943759b706f08c6c3f580be346f675fa3a8a7aa76b77871d6ec299a0d7befcbf6e
[00:14] <Runeblight> : 9643e03c4fed1422da9a30c0949af9202ecfdac591a105a4332b611952a1fc3e80b1b9389a873b84e7513a6cbeaa35427e4c983e11b659fcdc773f1915f315e139fb328b3ba37377c60321cc87eddabfe7bb34146deb50
[00:53] <Doomfang> : e241e1384bfb
[00:53] <Stormbane> : e241e1384bfb
[00:53] <Runeblight> : e241e1384bfb
```

I looked through the `server.py` and found the encryption algorithm:

```python
def encrypt(self, msg):
    encrypted_message = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(msg)
    return encrypted_message
```

The vulnerability here is that the key and nounce (counter) are the same for each encryption. So if we have some repeating patterns of ciphertext and we know some plaintext we can decrypt other encryted messages. Why we can do this? Well this is how CTR mode works, to be secured the counter has to change for each encryption, otherwise by xoring the ciphertext with other ciphertext we can deduce plaintext patterns, and if we know some plaintext we can find other plaintext based on those patterns. Just awesome!

Knowing this I looked through the encrypted messages and saw that the first 3 and last 3 messages are very similar. After playing a bit with this idea I discovered that the last 3 messages are `!leave` and the first 3 are `!nick <username>`.

Whith this knowledge I discovered the first bytes of every encrypted message and by guessing how to complete each sentence I succeded to decrypt the whole conversation.

In the `#general` channel I found the key to `#secret` and then used the same strategy to decrypt the conversation there and got the flag.

## Solution

Script to decrypt the conversation from `#general`:
```python
encrypted_str = [
    "f94ae3f4ea4b920b4696f6873f3f",
    "f94ae3f4ea4b85104689fd843036fc",
    "f94ae3f4ea4b8411479ef28a383ff1a7",
    "8f41ade1e44bb10b5ddbf1c63f3deef334bfbb8da1005a692ad5902f776ca27505c493b7238f699ecaeac49cb4b545f17f3880d7b12cefdcc8827573a2a176743504",
    "8d4aeef2f318a20b469fbec61939eaf334beaedfa54257793b9bc4267c35f0630ec691e462c9058fd6a8da9cadb547f3302285ccff28a7ced5cc6664ebb8627270468b6a5b6a1bf07705cc",
    "964bfeb7f80ea2480999e5927111bebe60b5a3c8a3095c7239d597287f29f06509d48cb16cc30588d7aad9ddb3a30ea11631d5d1f92afe9dcfc76b72aef762737c0a9d7c0f271ff86914d3a15a10e27d3165f5f3551575446cd669e135d7f4875406a8c238e9",
    "8c4ce3e4a108be054795f58a7131eaf32eb9bf8db30353797e938b353220bf7e00818ba561c456d59e81d2c8f8a300f2283e81c6f96ff3d29ccd7073eba76569264b9e7c0f3819f06c4e",
    "9041f8f2a102a5445d93f5c62139eaa030beb9ccb307157a3187c428673ef06302c28ab6688f4693dfa3d9d9b3ea00a4323ec7c2e707cffeea97635ea0b4753d0a1e9c4c633b19c64b469c9b",
    "9f4bfeb7e81ff8446695fc9f712bf1b232b3ebc4b44242752a9dc428673ef07d08d28be479dd5088caa8d39cbebc4ce83a24db",
    "8141f9b9a124a3160997f1952578f4bc36b3ebc0a11b15743f8381677e29b66447d58da56eca56d59e9ad29cb2a553f57f359085e72af5c49cc16473aeb1626c7e",
    "9103e7b7e203b3074292fe817137eca160baa4cab34241737e9781676139a27547cf90e479dd4498dbedd8daffbf55f37f3696d1f820e9ce9cd0606caabe79737e",
    "9341efe7a106b3445c8bf487253dfdfd609fad8db40a50657e9685337124f07f098ddfb3688849979ea5d6cabaf054ee7f3696d1b129e6cec88c",
    "9103e6fba108b909599ae283712cf1b660baaad9a511413c3a949026323bb9640f8190b17f8f479adda6c2ccffa04ce03179d5f2f46feac8cfd62564b9b66465704b84600f391ff86f4084ac1b11e22f202abdf54f1135",
    "9142aaf2f70ea41d5d93f9883678f0a060b5a7c8a110193c2990c42a7d3ab53013cedfb065ca0595dbb5c39caca441e63a79d5eae43da7dad3c36921a2a43777395e8270416a04fa60039be7",
    "904be6f3a104b84a09b2b78b712bfcb629b8ac8db316477d309281676125b77e06cd8ce46bdd4a969ea2c2c8acb944e47177a2c0b122eedad4d62563aef760612449827c4b64",
    "8f41aaf4e005f110098ff18d3478f8bd39f6b9c4b30946327eb98133353ff07c02c089a12ddb4d92cdedd4d4bebe4ee4337797c0f720f5d89cd66d64b2f76372314981395a3958",
    "9943f8f2e40ff8446494e6837139f5bf60a2aac1ab11156831d5902f776ca0620ed79eb0688f5794d1a0999c8da54ee43d3b9cc2f93bab9dccce6060b8b237633c4f8b6b0f3e1efa210c9cae4846ef38376ffb",
    "8d4aeef2f318a20b469fbec6187ff4f324bfb8ceaf0c5b793d818d29756cbe7f108fdf8d6b8f5193dbb497d4bea645a12c3290cbb13af4919cd56021a6a26474704e836a4e3a06fa6012d3a0560be2392c6ba1f5510d35",
    "f948eff6f70e",
    "f948eff6f70e",
    "f948eff6f70e"
]

encrypted_messages = [bytes.fromhex(x) for x in encrypted_str]

plain_messages = []

# this plaintext started as "!leave"
# eventually after finding more plaintext it grew into this sentance
plaintext = b"Understood. I'm disconnecting now. If they have seen us, we must disappear immediately "
c = encrypted_messages[17] # 17 is the index of the plaintext in encrypted_messages

for ciphertext in encrypted_messages:
    xor_leak = bytes(a ^ b for a, b in zip(ciphertext, c))
    plain_messages.append(bytes([x ^ y for x, y in zip(plaintext, xor_leak)]))

for i, plain in enumerate(plain_messages):
    print(i, plain) 
```

Decrypted conversation:

```
0 b'!nick Doomfang'
1 b'!nick Stormbane'
2 b'!nick Runeblight'
3 b"We've got a new tip about the rebels. Let's keep our chat private."
4 b'Understood. Has there been any sign of them regrouping since our last move?'
5 b"Not yet, but I'm checking some unusual signals. If they sense us, we might have to cha`"
6 b"This channel is not safe for long talks. Let's switch to our private room."
7 b'Here is the passphrase for our secure channel: %mi2gvHHCV5f_kcb=Z4vULqoYJ&oR'
8 b'Got it. Only share it with our most trusted allies.'
9 b'Yes. Our last move may have left traces. We must be very careful.'
10 b"I'm checking our logs to be sure no trace of our actions remains."
11 b"Keep me updated. If they catch on, we'll have to act fast."
12 b"I'll compare the latest data with our backup plan. We must erase any sign we were here "
13 b'If everything is clear, we move to the next stage. Our goal is within reach.'
14 b"Hold on. I'm seeing strange signals from outside. We might be watched."
15 b"We can't take any risks. Let's leave this channel before they track us."
16 b'Agreed. Move all talks to the private room. Runeblight, please clear the logs here.'
17 b"Understood. I'm disconnecting now. If they have seen us, we must disappear immediately "
18 b'!leave'
19 b'!leave'
20 b'!leave'
```

Key for `#secret` channel: `%mi2gvHHCV5f_kcb=Z4vULqoYJ&oR`

Script to decrypt the conversation from `#secret`
```python
import ast 

encrypted_str = [
    "d33d314bd2e36078843e505b7096",
    "d33d314bd2e3776384215b587f9fdd",
    "d33d314bd2e37662853654567796d03f",
    "a536785bd1ac517b8f735d5f7b819824c5d2cb2b694ebf25ce48a3387c45764bf1fe8354f701d442fcfdd2c63b6b128eb4ed716415d6d583d02be6bb91517f1a4bc963e66a7af167eed29ceae58cccd26c870e296b981f50965a1ccc3973ee4f7d710980d7b05f530d4f5f73",
    "b3342a4ddca70a37bf3b531a7b9fdd26c987987b764cbe3ed355e47f664f730eb2b1a559b251de45fbf1d39236640acce7847636049ede958468f4aa914c2d1a118c6ca86f7af260e88181eef9d583d1358d087b3c9d0e40971d06d77073f5577d660994d6bd5d1d054c5a38d88da06f4d4813838a30ff7912bf89eb630883618df12370ec202785f5dca1a0527258c395c41c735ad4042e8a471641a357b2d0296df6459a0770414c353d7237cde7c059c0c2",
    "bb742e4d99a141728573454e6b95c122dec7cb2f6d4af13fd547a77d6700684bb9aaf75ef749d259ecb8c29f73650b90e7bd6273069fd499d72bfcb09145630b069d6be76029a928e09c95abf89a81d2618a14677bd90d569b161b842b21ee517f3109accaa311530d575b328a87e76142061387cf29e02412808db82e0e957bd9bf2371b8613880fdc5e0b8493745de95d617365dc94f2f97100b11a857a093326cfb5e8603335e043b3c2079d1fdc009dc8ac5e2000085eab6c27d694346b0f11d10c474f28080ac60025667cdd2c9b8b1e661cd2c24fbe6be75d3233e25822e7c73ce36a729459cb32d2f223711abd1e0ce67567eb08240b1a86a07127d97a0f53205974c1ce0985f124940ad50d068873e61c0b538286ac7e2f640fd053ab9f5d63a6066c2a5db2746d2910e7c39670e9f5d396198cac3006d47aa29996d8222aca3f8f5f54e0a90f83e38aefb32659b321d49f7ec03d951",
    "bb743508d8af56728a374f1a7d83d738c38d8833604cba22c941e4776152245dafbbbb50e54ec95ca8f9c7873a640d96e7b978735097d58fcd6efbaad256681c089b66fb207acc6ea18699e2f8d58ed2748112673c8e0a40de0a09d62873ee59387e47c3d0bd55581a0349339b84a660504b0599de69ac1e158480eb68149e718def3e6ba32765c9d8def5f4537111d8c197106508c6473591110011a45db6dc7d76be548646644f4c322976729ef28559c18387fb164dcabf8bde32784549b9f11352f53cfad3c3a061145f6281d5c8b8b3e066d12024f5a4f93ad662253540cd876fc472f4240c9cbd78356b2319afd1b3996b4563b09c43a4eb6d06127e9da0e92214c54c06a59445574d0bad6cd971977970dbee",
    "a536784bd8ad4a789f73575c789eca2f90c88e286c5bb03fce49aa363469620eabb6be4fb248c817e9b8c294366b1d8aebed647e15989b98cc6eb5969b43655f248677e66d33e92ff2d297e4f99689c4358f1c703c9807419b1b0cdd7c31e41f7771098ccaa311491a424531d6cc827841484083c220ac245f8980a76b0e8435c0f63f70ad2a2ec9f9c4f4b85e3755dedada59795dd5042496130c43af12a2913072b7588f083d0a3b3f686d62cde7854adc8283fe014dc4feb68a7d754959f5fc5510ff69e9d3c1bd6c165466cdd4c9febae766c0366af4abe87f81613234cc6d7069cf22f5244dd5a1682365",
    "b72b394bcdaf5d39cb12585e3e94ce2ede80823d2558b46bd543a9797d4e245bb1adb259fc01dd58fab8ce8924265e95a2ed7e7315929b8fcb65e1b79c436811049022f8623beb7bafd2b8edab8184d235a1127c729a025fde1c07d6283ae7567d6c098acba211500944453e9980e76c4554129ecf37ff7b129f89eb6d128579c9bf206bbf246b88f9c8e4a7493745de95c3117341d504328c150a5fad5aae9c3971f811ac09335d097a206161dbb3c409c08986f81d4485edbb8a7f7e4b52a6b55c56b079f587d2b62f1e5c2399d8c9b8affb7cc82438e5eaf97bd5667738d16d6063c33ee22f1f",
    "ab362b0499a15163cb24531a7384cb3f90d4993e645bf122d306ab767859244facfeb61cfe40c843a8eac5953c780acce784763607939b8dc77ffca89350685f0e9d22fc6135a57bee9d9fa7ab828997678b0e623c8b0e459b1b04cd3234a1566c6c098fd0b25049014c4273d8a5b32e4d55409bcb27e93b578cccaa7d47d05df9dd3747be2829b6ded9e0b35d7e5fd6eaf2016644c84d3599130c5ea46d9699296a897a8d1f4c6403342b6548ecf6d05ad6cd98",
    "b53c374c97e36a78cb2153597183dc6bdfc6cb32710fbc3ed452e47d6c49775affb7b91ce649de17ffeac992276f10c2b3a27d7303d89ba5847cfcb29e046811149c70ed2e3be964a18683eae8909f9774901829798b0a409b1e44843d3de51f716b0990d7b05d51484d492b9d9ee76c41061387c52ee93912878aeb610d957bc1e6622485276b9df2cea1b154725cc895d20f735a87482499150b42ea5da7d03476fa119f03335d053624207fdfe5c009dd83c5e416438bf1a68a71734b52b6f01d",
    "b3342a4ddca70a37bf3b531a739eca2e90d78e7b6146a228d255b7387d54280eabb6b21cf553de56fcfdd2c627621bc2b5a4637d5ed6fe9ac179ecfe9f4b601a099d22ff6b7ae16ded9388a7ab8184d235a1127c729a025fde091cd6393de64b707a47909fb8454e4847493b9d82b46b570840a0cf65e122419cccaa6d09d066c2f02224ae242d86e8cea1bb4f6511c6dcd91d795f874b27d8081541a540b585336ba248c8057f451f3f3b2e",
    "a536785bd1ac517b8f7353547ad1cc23d9d3cb36604aa522c941e4797a442443b0a8b21ce64e9b56a8f5cf94362a0d87a4b862735085da82c77fe0b3dc044419479d6aed6728a565e09594f8ab9a9e976692146c6fd90a419b5a0bc83320e8517f3f408d93f145550d5a0c309995e7674a520585c920fc23128799b92e0a9f67c9ec62249b246b84efd8f5f454784591c1d6127308d34c208c470659ab5ca29573229a549c46674205296862729ee7cd4c938084e4070089fab1d9737c4f1cbcfb1344f875e8d3d0a36e145f2d",
    "d33f3d49cfa6",
    "d33f3d49cfa6",
    "d33f3d49cfa6"
] 

# know plain text at message 5: I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals to an unknown beacon-one that none of us au
encrypted_messages = [bytes.fromhex(x) for x in encrypted_str]
plain_messages = ast.literal_eval(open("secret.txt", "r").read())
i = 6
suffix = b"roblem. "
save = False
# save = True
plaintext = plain_messages[i] + suffix
c = encrypted_messages[i]

for i, ciphertext in enumerate(encrypted_messages):
    xor_leak = bytes(a ^ b for a, b in zip(ciphertext, c))
    plain_messages[i] = bytes([x ^ y for x, y in zip(plaintext, xor_leak)])

if save == True:
    open("secret.txt", "w").write(str(plain_messages[:16]))

for i, plain in enumerate(plain_messages):
    print(i, plain) 
```

Generally it is the same script, but I added some things to speed the process of finding plaintext bytes.

This is the decrypted conversation:

```
0 b'!nick Doomfang'
1 b'!nick Stormbane'
2 b'!nick Runeblight'
3 b'We should keep our planning here. The outer halls are not secure, and too many eyes watch the open channels.'
4 b"Agreed. The enemy's scouts grow more persistent. If they catch even a whisper of our designs, they will move against us. We must not allow their seers or spies to track our steps."
5 b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals to an unknown beacon-one that none of us au"
6 b"I'm already cross-checking our spellwork against the ancient records. If this beacon was part of an older enchantment, I'll find proof. But if it is active now, then we have a problem. "
7 b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom our entire campaign. We must confirm a"
8 b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could lose access to their strongholds. Do we have a secondar'
9 b'Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location. It is labeled as: HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}'
10 b'Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never be spoken of openly. If the enemy ever learns of it, we will have no secon'
11 b'Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses. We must act soon before our window of opportunity closes.'
12 b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our words. We must not take that chance. Let this be the last me'
13 b'!leave'
14 b'!leave'
15 b'!leave'
```

### Flag

`HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}`
