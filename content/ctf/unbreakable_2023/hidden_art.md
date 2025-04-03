---
title: Hidden Art
date: 2023-05-24T21:44:04+03:00
tags:
  - stego
  - forensics
type: writeup
author: H0N3YP0T
---

```python

import heapq
import pickle


# We use a huffman tree because we have a dict whith the char frequency

class Node:
    def __init__(self, char, freq, left_node=None, right_node=None):
        self.char = char
        self.freq = freq
        self.left_node = left_node
        self.right_node = right_node

    def __lt__(self, other):
        return self.freq < other.freq


def generate_huffman_tree(freq_dict):
    # Create a priority queue from the frequency dictionary
    priority_queue = [Node(char, freq) for char, freq in freq_dict.items()]
    heapq.heapify(priority_queue)

    # Iteratively combine the two nodes with the lowest frequencies
    while len(priority_queue) > 1:
        low_node = heapq.heappop(priority_queue)
        high_node = heapq.heappop(priority_queue)
        combined_node = Node(None, low_node.freq + high_node.freq, low_node, high_node)
        heapq.heappush(priority_queue, combined_node)

    return priority_queue[0]  # The remaining node is the root of the Huffman tree


def generate_huffman_codes(root):
    huff_codes = {}

    def generate_codes_recursive(node, current_code):
        if node is None:
            return
        if node.char is not None:
            huff_codes[node.char] = current_code
            return
        generate_codes_recursive(node.left_node, current_code + '0')
        generate_codes_recursive(node.right_node, current_code + '1')

    generate_codes_recursive(root, '')
    return huff_codes


def decode_huffman(huff_codes, binary_str):
    decoded_str = ''
    current_code = ''
    for bit in binary_str:
        current_code += bit
        for char, code in huff_codes.items():
            if current_code == code:
                decoded_str += char
                current_code = ''
                break
    return decoded_str


# Load your pickle file
with open('data_freq.pkl', 'rb') as handle:
    frequency_dictionary = pickle.load(handle)

# Generate the Huffman tree and Huffman codes
root = generate_huffman_tree(frequency_dictionary)
huff_codes = generate_huffman_codes(root)

# Read your binary file
with open('e-dummy.txt', 'r') as file:
    binary_data = file.read().replace('\n', '')

# Decode the binary file
decoded_str = decode_huffman(huff_codes, binary_data)

print(f"Decoded String: {decoded_str}")

```
