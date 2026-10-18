# Bytecode Bakery

| Field | Value |
|---|---|
| Challenge | Bytecode Bakery |
| Category | Reverse Engineering |
| Source PDF pages | 27–29 |
| Team name | Not specified in the source PDF |
| Solver names | Not specified in the source PDF |

> This document faithfully formats the technical content from the supplied local PDF. No technical steps, commands, evidence, or flags were added.

The bakery's oven runs its own tiny instruction set. The recipe card checks whether you
know the secret ingredient list. Find the ingredients that bake a perfect loaf.

## Challenge Details & Overview

- Supplied files: oven.py & recipe.bin
- Recovered NEXSEC26 flag : nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}


## Test the flag on Linux Mint

Put oven.py and recipe.bin in the same directory.


When it displays: Enter ingredient list:

Paste the recovered flag and press Enter.

The expected response is: Fresh from the oven! Submit the ingredient list as the flag.


## Reproduce the solution with a Python solver

I've write a script that reverses the bytecode checks and reconstructs the flag automatically.

solve_recipe.py

Save it in the same directory as the two challenge files:

Downloads/
├── oven.py
├── recipe.bin
└── solve_recipe.py

Then run:


Expected output:

Input length: 50; real code begins at 0x00ec
Recovered ingredient list: nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}
Original oven accepts input: True

## Source Figures

![Original writeup figure — PDF page 27](../../assets/bytecode-bakery/figure-018.png)

*Original writeup figure — PDF page 27*

![Original writeup figure — PDF page 28](../../assets/bytecode-bakery/figure-019.png)

*Original writeup figure — PDF page 28*

![Original writeup figure — PDF page 28](../../assets/bytecode-bakery/figure-020.png)

*Original writeup figure — PDF page 28*

![Original writeup figure — PDF page 29](../../assets/bytecode-bakery/figure-021.png)

*Original writeup figure — PDF page 29*
