# Very Fest

| Field | Value |
|---|---|
| Challenge | Very Fest |
| Category | Reverse Engineering |
| Team name | B2F1 |

## Deepseek Chat Link
DeepSeek Conversation Link: https://chat.deepseek.com/share/cq0c01jdowfxrz5jz5

## What we were given

Before touching anything, we went through everything in the handout:

- README.md: a single line, "Bytecode analysis made easy (re.hanz.dev)." It’s short but it does
       two things. It tells us the category is bytecode analysis, and the .evm on the attachment plus
       the "re" in the domain tells us which kind: this is EVM bytecode, the compiled form of an
       Ethereum smart contract. So the whole challenge is reading a compiled program, not running
       an exploit against a live service.
- VeryFest.evm: the actual artifact. It's a 1,264-character hex string, which is just the raw bytes
       of a deployed contract written out two hex digits per byte. There's no live instance to
       connect to and nothing to log into; everything we need is inside this one file.

That framing mattered. With no server in the loop, the flag can't be something the contract
computes and hands back over a network. It has to already be inside the bytes, either as logic we
reverse or as data we read out. That pushed us toward reading the file rather than deploying and
calling it.


## Figuring out where to look

We didn't disassemble the whole thing. We just looked at the first handful of bytes, because the
opening of an EVM contract is pretty formulaic and it tells you a lot.

It starts with ...5f3560e01c63146e61ed8114.... The 5f3560e01c bit is the standard opener every
Solidity-style contract has: it grabs the first 4 bytes of your input and treats them as a function
selector (which function you're trying to call). Right after that, 63 <4 bytes> 81 14 ... 57 shows up
three times in a row, which is three "if the selector equals X, jump over here" checks. So the contract
has three entry points and sends you down different paths depending on which one you hit.

Put together, this is a "give me the right input and I'll tell you you're right" contract. You hand it some
bytes, it compares them against a secret, and if everything matches it fires off a success event.
Classic shape, and it comes with a classic shortcut.

Here's the shortcut. In EVM, anything a contract compares against has to get pushed onto the stack
first with a PUSH instruction, and the bytes it pushes are written right there inline, immediately after
the opcode. The ones that matter here are 0x7f (PUSH32, push the next 32 bytes) and 0x61 (PUSH2,
push the next 2). So the secret the contract is checking you against is literally stored in the file as
plain data. We don't need to understand the comparison, deploy anything, or simulate the VM. We
just need to pull those pushed bytes out and turn them from hex into text.

## How we actually did it

First we loaded the hex and turned it back into raw bytes, which is just chewing through the string
two characters at a time (every pair of hex digits is one byte).

Then we did the lazy-but-effective thing: a string scan. Most of the bytes are opcodes and come out
as garbage if you print them, but the embedded text constants are real readable ASCII sitting in the
middle of that noise. So we printed everything, dropped in a line break every time we hit a
non-printable byte, and kept only the lines that were at least 4 characters long. That's basically what
the strings tool does, and it pulls the readable bits out of the mess.

Three fragments fell out of that:

- nexsec26{decentralization_means_
- giving_up_dominance_over_securit
- y} — this one was tucked inside a line that printed as V[ay}

The first two are 32 bytes each (the two PUSH32 constants), and the last one is the 2-byte PUSH2.
That split isn't random. The flag is 66 characters, and a PUSH32 only holds 32 bytes, so the contract
can't check the whole thing in one go. It compares it in 32 + 32 + 2 chunks, pushing each piece and
running an EQ against a slice of your input, and all three have to pass. So the three fragments are just
the flag cut into the sizes the VM could handle.

The V[a junk in front of the y} is nothing, by the way, it's just the neighbouring opcodes (5b is
JUMPDEST, 61 is PUSH2) that happened to land on printable values. You ignore that and keep the y}.

Glue them together in order:

nexsec26{decentralization_means_ + giving_up_dominance_over_securit + y}

and you get:

nexsec26{decentralization_means_giving_up_dominance_over_security}

The thing that told us we had the order right: the words run straight across the cut points. means_
ends the first chunk, securit ends the second, y} finishes it off. If we'd stitched them wrong the
sentence would've been gibberish, so the fact that it reads cleanly was the confirmation.


## The flag

nexsec26{decentralization_means_giving_up_dominance_over_security}

Kind of a cheeky one too, a decentralization slogan hidden inside a contract, and the "security" at the
end is exactly what the challenge name is needling at ("Very Fest" / verify).


Steps to reproduce
Everything below is PowerShell, run from the folder that has VeryFest.evm in it.

powershell:
cd "C:\Users\yikka\OneDrive\Desktop\CTF\Very Fest"
# 1. read the file, strip out any spaces or newlines
$bc = (Get-Content .\VeryFest.evm -Raw) -replace '\s',''
# 2. hex string -> raw bytes
$bytes = for ($i=0; $i -lt $bc.Length; $i+=2) { [Convert]::ToByte($bc.Substring($i,2),16) }
# 3. bytes -> text, with a line break wherever a byte isn't printable
$text = -join ($bytes | ForEach-Object { if ($_ -ge 0x20 -and $_ -le 0x7e) { [char]$_ } else { "`n" } })
# 4. strings view: show every run of 4+ printable chars
$text -split "`n" | Where-Object { $_.Length -ge 4 }

That dumps the three fragments. To get a clean flag without eyeballing it, decode the exact pushed
constants from their hex and join them:

powershell:
# hex -> ASCII (this version also works on old Windows PowerShell 5.1)
function Hex2Str($h){ -join ($h -split '(..)' | Where-Object {$_} | ForEach-Object
{[char][Convert]::ToByte($_,16)}) }
$h1 = "6e657873656332367b646563656e7472616c697a6174696f6e5f6d65616e735f" # chunk 1
$h2 = "676976696e675f75705f646f6d696e616e63655f6f7665725f73656375726974" # chunk 2
$h3 = "797d"                                        # chunk 3 -> "y}"
$flag = (Hex2Str $h1) + (Hex2Str $h2) + (Hex2Str $h3)
$flag

Output:

nexsec26{decentralization_means_giving_up_dominance_over_security}

Here's the whole thing running end to end, the strings scan surfacing the three fragments and the
final assembly spitting out the flag:

One gotcha worth flagging: if you write Hex2Str with a for loop inside -join (...), Windows PowerShell
5.1 throws a pile of "missing closing parenthesis" errors, because it won't let a for statement be used
as an expression. The -split '(..)' version above dodges that and runs on both 5.1 and 7.


## Why it worked / what to remember

The whole thing hangs on one fact about the EVM: a value a contract compares against is a PUSH
immediate, and immediates lives inline in the bytecode as plain data. So any secret the contract
checks is also a secret the contract contains. No deploy, no RPC, no simulation needed — if it's doing
an equality check, the answer is already in the file.

A couple of patterns to keep in your back pocket for next time. Seeing 5f3560e01c (or 6000...60e01c)
near the top means selector dispatch, i.e. a multi-function contract. And 7f is PUSH32 — the whole
60–7f range is PUSH1 through PUSH32. Any time you spot printable ASCII right after one of those and
it's feeding into an EQ (14), that's a comparison constant, and in a CTF that's almost always the flag
or a slice of it. When the target is longer than 32 bytes, expect it chopped into 32-byte chunks with a
short push for the leftover, exactly like the 32 + 32 + 2 here. Reassemble in push order and the words
line up.

## Source Figures

![Original writeup figure](../../assets/very-fest/figure-028.png)

![Original writeup figure](../../assets/very-fest/figure-029.png)

