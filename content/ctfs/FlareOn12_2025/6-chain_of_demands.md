---
title: 6.chain_of_demands 
type: writeup
date: 2025-10-01T18:42:50+02:00
description: Writeup for chain_of_demands [FlareOn 2025]
author: PineBel
tags:
- rev
- crypto
draft: false
---


While I didn't solve this challenge, I feel I was pretty close but got sidetracked down a rabbit hole.  
For this challenge we get a Linux executable. When running it we get a console application that acts as a chat client.  
The most important part of this is that we have a `Last Convo` button which displays the following:

```json
[
  {
    "conversation_time": 0,
    "mode": "LCG-XOR",
    "plaintext": "Hello",
    "ciphertext": "e934b27119f12318fe16e8cd1c1678fd3b0a752eca163a7261a7e2510184bbe9"
  },
  {
    "conversation_time": 4,
    "mode": "LCG-XOR",
    "plaintext": "How are you?",
    "ciphertext": "25bf2fd1198392f4935dcace7d747c1e0715865b21358418e67f94163513eae4"
  },
  // 5 more LCG-XOR messages 
  {
    "conversation_time": 242,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "680a65364a498aa87cf17c934ab308b2aee0014aee5b0b7d289b5108677c7ad1eb3bcfbcad7582f87cb3f242391bea7e70e8c01f3ad53ac69488713daea76bb3a524bd2a4bbbc2cfb487477e9d91783f103bd6729b15a4ae99cb93f0db22a467ce12f8d56acaef5d1652c54f495db7bc88aa423bc1c2b60a6ecaede2f4273f6dce265f6c664ec583d7bd75d2fb849d77fa11d05de891b5a706eb103b7dbdb4e5a4a2e72445b61b83fd931cae34e5eaab931037db72ba14e41a70de94472e949ca3cf2135c2ccef0e9b6fa7dd3aaf29a946d165f6ca452466168c32c43c91f159928efb3624e56430b14a0728c52f2668ab26f837120d7af36baf48192ceb3002"
  },
  {
    "conversation_time": 249,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "6f70034472ce115fc82a08560bd22f0e7f373e6ef27bca6e4c8f67fedf4031be23bf50311b4720fe74836b352b34c42db46341cac60298f2fa768f775a9c3da0c6705e0ce11d19b3cbdcf51309c22744e96a19576a8de0e1195f2dab21a3f1b0ef5086afcffa2e086e7738e5032cb5503df39e4bf4bdf620af7aa0f752dac942be50e7fec9a82b63f5c8faf07306e2a2e605bb93df09951c8ad46e5a2572e333484cae16be41929523c83c0d4ca317ef72ea9cde1d5630ebf6c244803d2dc1da0a1eefaafa82339bf0e6cf4bf41b1a2a90f7b2e25313a021eafa6234643acb9d5c9c22674d7bc793f1822743b48227a814a7a6604694296f33c2c59e743f4106"
  }
]
```

So it's clear that we need to decrypt the RSA-encrypted messages. We also receive a public key for the RSA from that convo.

When RE-ing it, it's pretty clear that it's a PyInstaller-packed binary. To unpack it I used `pyinstxtractor` (https://github.com/extremecoders-re/pyinstxtractor).  
After that I analyzed the contents a bit and found a file called `challenge_to_compile.pyc` since this seemed to be the most important file, so I decided to decompile it.

To decompile it I used `pycdc` (https://github.com/zrax/pycdc), but it was failing, so I followed this guide to bypass the errors: https://idafchev.github.io/blog/Decompile_python/.  
While reading other writeups I found that we could also use https://pylingual.io/, which is pretty accurate.  
Or we could just disassemble the bytecode with the built-in disassembler and give it to Claude AI (see: https://gist.github.com/superfashi/563425ee96d505c0263373230335e41a#6---chain-of-demands).

The code also uses some smart contracts to do the computations for the LCG‑XOR. Since I got sidetracked thinking something was wrong with my decompiled code, I deployed the contracts locally with Ganache to ensure I hadn't made a mistake (fun fact: I didn't).  
We could also look at the decompiled EVM bytecode of the contracts on [Dedaub](https://app.dedaub.com/decompile).

The code where the contracts are locally deployed (there are also some minor changes I made to test things):

```py
import sys
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
import hashlib
import platform
import time
import math
import os
from Crypto.Util.number import inverse
from web3 import Web3



def resource_path(relative_path):
    '''
    Get the absolute path to a resource, which works for both development
    and for a PyInstaller-bundled executable.
    '''
    base_path = sys._MEIPASS
    return os.path.join(base_path, relative_path)
    if Exception:
        base_path = os.path.abspath('.')


class LCGOracle:
    
    def __init__(self, multiplier, increment, modulus, initial_seed):
        self.multiplier = multiplier
        self.increment = increment
        self.modulus = modulus
        self.state = initial_seed
        self.contract_bytes = '6080604052348015600e575f5ffd5b506102e28061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063115218341461002d575b5f5ffd5b6100476004803603810190610042919061010c565b61005d565b6040516100549190610192565b60405180910390f35b5f5f848061006e5761006d6101ab565b5b86868061007e5761007d6101ab565b5b8987090890505f5f8411610092575f610095565b60015b60ff16905081816100a69190610205565b858260016100b49190610246565b6100be9190610205565b6100c89190610279565b9250505095945050505050565b5f5ffd5b5f819050919050565b6100eb816100d9565b81146100f5575f5ffd5b50565b5f81359050610106816100e2565b92915050565b5f5f5f5f5f60a08688031215610125576101246100d5565b5b5f610132888289016100f8565b9550506020610143888289016100f8565b9450506040610154888289016100f8565b9350506060610165888289016100f8565b9250506080610176888289016100f8565b9150509295509295909350565b61018c816100d9565b82525050565b5f6020820190506101a55f830184610183565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61020f826100d9565b915061021a836100d9565b9250828202610228816100d9565b9150828204841483151761023f5761023e6101d8565b5b5092915050565b5f610250826100d9565b915061025b836100d9565b9250828203905081811115610273576102726101d8565b5b92915050565b5f610283826100d9565b915061028e836100d9565b92508282019050808211156102a6576102a56101d8565b5b9291505056fea2646970667358221220c7e885c1633ad951a2d8168f80d36858af279d8b5fe2e19cf79eac15ecb9fdd364736f6c634300081e0033'
        self.contract_abi = [
            {
                'inputs': [
                    {
                        'internalType': 'uint256',
                        'name': 'LCG_MULTIPLIER',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': 'LCG_INCREMENT',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': 'LCG_MODULUS',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': '_currentState',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': '_counter',
                        'type': 'uint256' }],
                'name': 'nextVal',
                'outputs': [
                    {
                        'internalType': 'uint256',
                        'name': '',
                        'type': 'uint256' }],
                'stateMutability': 'pure',
                'type': 'function' }]
        self.deployed_contract = None

    def connect_local(self):
        self.web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        if not self.web3.is_connected():
            raise Exception("Cannot connect to local blockchain")
        self.account = self.web3.eth.accounts[0]  
        self.web3.eth.default_account = self.account 

    def deploy_contract(self):
        # Create contract factory
        contract_factory = self.web3.eth.contract(
            abi=self.contract_abi,
            bytecode=self.contract_bytes
        )

        # Deploy contract
        tx_hash = contract_factory.constructor().transact()
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        # Create deployed contract instance
        self.deployed_contract = self.web3.eth.contract(
            address=tx_receipt.contractAddress,
            abi=self.contract_abi
        )

        print(f"Contract deployed at: {tx_receipt.contractAddress}")
        return self.deployed_contract  # Return the deployed instance


    def get_next(self, counter):
        if not self.deployed_contract:
            raise Exception("Contract not deployed yet")

        print(f"\n[+] Calling nextVal() with _currentState={self.state}")
        
        # Call the nextVal function on the deployed contract
        self.state = self.deployed_contract.functions.nextVal(
            self.multiplier,
            self.increment,
            self.modulus,
            self.state,
            counter
        ).call()

        print(f"  _counter = {counter}: Result = {self.state}")
        return self.state

   # def get_next(self, counter):
   #     # Apply the LCG formula
   #     for _ in range(counter):
   #         self.state = (self.multiplier * self.state + self.increment) % self.modulus
   #     #print(f'''[+] LCG Next Value: {self.state} (Counter: {counter})''')
   #     return self.state


class TripleXOROracle:
    
    def __init__(self):
        self.contract_bytes = '61030f61004d600b8282823980515f1a6073146041577f4e487b71000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b305f52607381538281f3fe7300000000000000000000000000000000000000003014608060405260043610610034575f3560e01c80636230075614610038575b5f5ffd5b610052600480360381019061004d919061023c565b610068565b60405161005f91906102c0565b60405180910390f35b5f5f845f1b90505f845f1b90505f61007f85610092565b9050818382181893505050509392505050565b5f5f8290506020815111156100ae5780515f525f5191506100b6565b602081015191505b50919050565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b6100df816100cd565b81146100e9575f5ffd5b50565b5f813590506100fa816100d6565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b61014e82610108565b810181811067ffffffffffffffff8211171561016d5761016c610118565b5b80604052505050565b5f61017f6100bc565b905061018b8282610145565b919050565b5f67ffffffffffffffff8211156101aa576101a9610118565b5b6101b382610108565b9050602081019050919050565b828183375f83830152505050565b5f6101e06101db84610190565b610176565b9050828152602081018484840111156101fc576101fb610104565b5b6102078482856101c0565b509392505050565b5f82601f83011261022357610222610100565b5b81356102338482602086016101ce565b91505092915050565b5f5f5f60608486031215610253576102526100c5565b5b5f610260868287016100ec565b9350506020610271868287016100ec565b925050604084013567ffffffffffffffff811115610292576102916100c9565b5b61029e8682870161020f565b9150509250925092565b5f819050919050565b6102ba816102a8565b82525050565b5f6020820190506102d35f8301846102b1565b9291505056fea26469706673582212203fc7e6cc4bf6a86689f458c2d70c565e7c776de95b401008e58ca499ace9ecb864736f6c634300081e0033'
        self.contract_abi = [
            {
                'inputs': [
                    {
                        'internalType': 'uint256',
                        'name': '_primeFromLcg',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': '_conversationTime',
                        'type': 'uint256' },
                    {
                        'internalType': 'string',
                        'name': '_plaintext',
                        'type': 'string' }],
                'name': 'encrypt',
                'outputs': [
                    {
                        'internalType': 'bytes32',
                        'name': '',
                        'type': 'bytes32' }],
                'stateMutability': 'pure',
                'type': 'function' }]
        self.deployed_contract = None

    
 
    def deploy_triple_xor_contract(self):
        contract_factory = self.web3.eth.contract(
        abi=self.contract_abi,
        bytecode=self.contract_bytes)

        tx_hash = contract_factory.constructor().transact()
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        # Create deployed contract instance
        self.deployed_contract = self.web3.eth.contract(
            address=tx_receipt.contractAddress,
            abi=self.contract_abi
        )

        print(f"Contract deployed at: {tx_receipt.contractAddress}")
        return self.deployed_contract  # Return the deployed instance

    def connect_local(self):
        self.web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        if not self.web3.is_connected():
            raise Exception("Cannot connect to local blockchain")
        self.account = self.web3.eth.accounts[0]  
        self.web3.eth.default_account = self.account 

    def encrypt(self, prime_from_lcg, conversation_time, plaintext_bytes):
        print(f'''\n[+] Calling encrypt() with prime_from_lcg={prime_from_lcg}, time={conversation_time}, plaintext={plaintext_bytes}''')
        ciphertext = self.deployed_contract.functions.encrypt(prime_from_lcg, conversation_time, plaintext_bytes).call()
        print(f'''  _ciphertext = {ciphertext.hex()}''')
        return ciphertext

def get_seed():
    artifact = platform.node().encode('utf-8')
    hash_val = hashlib.sha256(artifact).digest()
    seed_hash = int.from_bytes(hash_val, 'little')
    #seed_hash = 72967016216206426977511399018380411256993151454761051136963936354667101207529
    return seed_hash

def generate_primes_from_hash(seed_hash):
    primes = []
    current_hash_byte_length = (seed_hash.bit_length() + 7) // 8
    current_hash = seed_hash.to_bytes(current_hash_byte_length, 'little')
    print('[SETUP] Generating LCG parameters from system artifact...')
    iteration_limit = 10000
    iterations = 0
    while len(primes) < 3 and iterations < iteration_limit:
        current_hash = hashlib.sha256(current_hash).digest()
        candidate = int.from_bytes(current_hash, 'little')
        iterations += 1
        if candidate.bit_length() == 256 and isPrime(candidate):
            primes.append(candidate)
            print(f'[SETUP]  - Found parameter {len(primes)}: {str(candidate)[:20]}...')
    if len(primes) < 3:
        error_msg = '[!] Error: Could not find 3 primes within iteration limit.'
        print('Current Primes: ', primes)
        print(error_msg)
        exit()
    return (primes[0], primes[1], primes[2])

seed_hash = get_seed()
m, c, n = generate_primes_from_hash(seed_hash)
lcg_oracle = LCGOracle(m,c,n,seed_hash)
lcg_oracle.connect_local()
lcg_oracle.deploy_contract()
xor_oracle = TripleXOROracle()
xor_oracle.connect_local()
xor_oracle.deploy_triple_xor_contract()

d = 0
n = 0
def generate_rsa_key_from_lcg():
    global n
    global d
    print('[RSA] Generating RSA key from on-chain LCG primes...')
    lcg_for_rsa = LCGOracle(lcg_oracle.multiplier, lcg_oracle.increment, lcg_oracle.modulus, seed_hash)
    lcg_for_rsa.connect_local()
    lcg_for_rsa.deploy_contract()

    primes_arr = []
    rsa_msg_count = 0
    iteration_limit = 10000
    iterations = 0
    while len(primes_arr) < 8 and iterations < iteration_limit:
        candidate = lcg_for_rsa.get_next(rsa_msg_count)
        rsa_msg_count += 1
        iterations += 1
        if candidate.bit_length() == 256 and isPrime(candidate):
            if candidate not in primes_arr:
                primes_arr.append(candidate)
                print(f'[RSA] - Found 256-bit prime #{len(primes_arr)}')

    print('Primes Array: ', primes_arr)
    if len(primes_arr) < 8:
        error_msg = '[RSA] Error: Could not find 8 primes within iteration limit.'
        print(error_msg)
        return error_msg

    n = 1  
    for p_val in primes_arr:
        n *= p_val
    phi = 1
    for p_val in primes_arr:
        phi *= p_val - 1

    e = 65537
    if math.gcd(e, phi) != 1:
        error_msg = '[RSA] Error: Public exponent e is not coprime with phi(n). Cannot generate key.'
        print(error_msg)
        return error_msg

    rsa_key = RSA.construct((n, e))
    with open("testpublic.pem", "wb") as f:
        f.write(rsa_key.export_key("PEM"))

    print("[RSA] Keys saved to private.pem and public.pem")
    return rsa_key


#rsa_key = generate_rsa_key_from_lcg()
rsa_key = ''
seed_hash = get_seed()
m, c, n = generate_primes_from_hash(seed_hash)
lcg_oracle = LCGOracle(m,c,n,seed_hash)
lcg_oracle.connect_local()
lcg_oracle.deploy_contract()
xor_oracle = TripleXOROracle()
xor_oracle.connect_local()
xor_oracle.deploy_triple_xor_contract()

option = int(sys.argv[1]) 
message = str(sys.argv[2])
#seed_hash = 72967016216206426977511399018380411256993151454761051136963936354667101207529
message = "How are you?"
message_count = 1
conversation_start_time = 0

def process_message(plaintext):
    global conversation_start_time
    global message_count
    if conversation_start_time == 0:
        conversation_start_time = time.time()
    conversation_time = 4
    print(conversation_time)
    if option == 5:
        plaintext_bytes = plaintext.encode('utf-8')
        plaintext_enc = bytes_to_long(plaintext_bytes)
        _enc = pow(plaintext_enc, rsa_key.e, rsa_key.n)
        ciphertext = _enc.to_bytes(rsa_key.n.bit_length(), 'little').rstrip(b'\x00')
        encryption_mode = 'RSA'
        plaintext = '[ENCRYPTED]'
    else:
        prime_from_lcg = lcg_oracle.get_next(message_count)
        ciphertext = xor_oracle.encrypt(prime_from_lcg, conversation_time, plaintext)
        encryption_mode = 'LCG-XOR'
    log_entry = {
        'conversation_time': conversation_time,
        'mode': encryption_mode,
        'plaintext': plaintext,
        'ciphertext': ciphertext.hex() }
    message_count += 1
    return (f'''[{conversation_time}s] {plaintext}''', f'''[{conversation_time}s] {ciphertext.hex()}''')
```

So basically what this program does is:

* Generate a seed based on the host machine name. With this seed, three prime numbers are computed for the LCG (`m`, `c`, and `n`).  
* The seed and the three prime numbers are also used in the RSA key pair.

The LCG algorithm is pretty intuitive and does the following:

```py
def gen_next(self, counter):
    for _ in counter:
        self.state = (self.multiplier * self.state + self.increment)  % self.modulus
    return self.state
```

The triple XOR just takes the time, the text, and the LCG value and XORs them to get the ciphertext.

The bug comes from the fact that the first time the LCG is used, if the counter is zero the state itself is returned which is actually the seed (this is visible in the LCG constructor). So with the first message from the conversation we can retrieve the original seed since we have the time, the message and the ciphertext:

    ciphertext = message ^ time ^ seed
    => seed = ciphertext ^ time ^ message

So with the logic of the program, I expected to get the RSA keys with this seed. This doesn't happen which is really strange since it should do this.
I also tested it with local conversations and it worked. Here is where I fell into a rabbit hole and thought I missed something.
Apperantly the conversation that we get isn't generated with this program.

The actual solution for this is to reverse the LCG algorithm to compute the multiplier, increment and the modulus based on the seed we leaked.
There is a nice [resource](https://msm.lt/posts/cracking-rngs-lcgs/) on this which explain the math nicely.
But the main idea is that we can find the modulus by using the fact that random multiples of x, most likely have the gcd x. To use this we need to transform our expressions into a form where we have X = d*modulus.

My solve script:
```py
import json
import math
from functools import reduce
from sympy import isprime as isPrime

lcg_values = []
rsa_texts = []
conversations = json.load(open("chat_log_original.json", "r"))
messages = []
for msg in conversations:
    messages.append((msg["conversation_time"], msg["plaintext"], msg["ciphertext"]))
    lcg_values.append((msg["conversation_time"] ^ int.from_bytes(msg["plaintext"].encode('utf-8')[:32].ljust(32, b'\x00'), 'big') ^ int(msg["ciphertext"],16)))

# only need the LCG values
lcg_values = lcg_values[:7]
rsa_texts = messages[7:]

for i, v in enumerate(lcg_values):
    print(f"LCG state {i}: {v}")

# These values follow the LCG formula: X_{n+1} = (a * X_n + c) mod m
# So now we need to solve a,c and m for X_0, X_1, X_2, ..., X_6

#compute the differences to eliminate c to use the target equation (t2*t0 - t1*t1 = (m*m*t0 * t0) - (m*t0 * m*t0) = 0 (mod n))
t = [s1-s0 for s0, s1 in zip(lcg_values, lcg_values[1:])]
zero_mods = [t2*t0 - t1*t1 for t0, t1, t2 in zip(t, t[1:], t[2:])]

# try to compute the gcd of these values to get m
m = abs(reduce(math.gcd, zero_mods))
print(f"Modulus m: {m}")

# just solve the equations to get a and c
a = (lcg_values[3] - lcg_values[2]) * pow(lcg_values[2] - lcg_values[1], -1, m) % m 
print(f"Multiplier a: {a}")

c = (lcg_values[1] - lcg_values[0]*a) % m

print(f"Increment c: {c}")

original = (lcg_values[0]- c) * pow(a, -1, m) % m
print(f"seed: {original}")


# use the RSA implementation from generate_rsa_from_lcg
primes_arr = []
rsa_msg_count = 0
iteration_limit = 10000
iterations = 0
while len(primes_arr) < 8 and iterations < iteration_limit:
    candidate = (a * original + c) % m
    original = candidate
    iterations += 1
    if candidate.bit_length() == 256 and isPrime(candidate):
        if candidate not in primes_arr:
            primes_arr.append(candidate)

print('Primes Array: ', primes_arr)

n = 1  
for p_val in primes_arr:
    n *= p_val
phi = 1
for p_val in primes_arr:
    phi *= p_val - 1
e = 65537
d = pow(e, -1, phi)

for text in rsa_texts:
    c = int.from_bytes(bytes.fromhex(text[2]), 'little')
    msg_int = pow(c, d, n)
    msg_bytes = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
    msg_str = msg_bytes.decode('utf-8')
    print(msg_str)
```

While I don't like the fact that the conversation was generated with another code, I should've stepped back and iterated again on what information I had.
There are also persons that solved this using [factordb](http://www.factordb.com/) with the [result](http://www.factordb.com/index.php?query=966937097264573110291784941768218419842912477944108020986104301819288091060794069566383434848927824136504758249488793818136949609024508201274193993592647664605167873625565993538947116786672017490835007254958179800254950175363547964901595712823487867396044588955498965634987478506533221719372965647518750091013794771623552680465087840964283333991984752785689973571490428494964532158115459786807928334870321963119069917206505787030170514779392407953156221948773236670005656855810322260623193397479565769347040107022055166737425082196480805591909580137453890567586730244300524109754079060045173072482324926779581706647).
