# Paradise

| Field | Value |
|---|---|
| Challenge | Paradise |
| Category | Crypto |
| Team name | B2F1 |

## What we were given

One file, chall.py, and a netcat endpoint. Reading the source, here's exactly what the
service does per connection:


seed = randbytes(8)       # 8 secret random bytes
rng = Random(seed)          # Python's Mersenne Twister, seeded from those bytes
secret = rng.getrandbits(32) # a hidden 32-bit value we never see

standart = 624*32
for _ in range(standart//20 - 32): # == 966 iterations
   x = rng.getrandbits(32)
   something.append(x >> 16)          # only the TOP 16 bits of each output
print(something)                # the 966 truncated values are printed to us


Then it asks us, three times, for Seed (hex) and Secret. If both match, it prints the flag.

So the whole challenge is: from 966 values, each being getrandbits(32) >> 16 (the top 16
bits only), recover the original 8-byte seed and the hidden secret.

Two numbers mattered from the start:

- 966 outputs × 16 known bits = 15,456 bits of information handed to us.
- Python's MT19937 internal state is 624 × 32 = 19,968 bits.

We're given less data than the state is big. That single fact is the whole puzzle, and it's why
the obvious approach doesn't work.


## How we read the problem (our starting direction)

Python's random module is the Mersenne Twister (MT19937). The important property, the
one every one of these challenges leans on, is that each output bit is a linear (XOR)
function of the 19,968 internal state bits over GF(2). The twist step and the tempering
step are both linear, so once you lay the state out as symbolic bits, every number the RNG
spits out becomes a bunch of XOR equations in those bits. Collect enough equations, solve
the linear system, and you've cloned the RNG. That's the classic cryptopals-style attack.

So our first instinct was the textbook move: rebuild the full state from the outputs, then roll it
backwards to the seed and forwards to secret.

That instinct runs straight into a wall, and the wall is the point of the challenge:

- Full state recovery needs on the order of 19,937 independent output bits. We have
      15,456. We are about 4,500 bits short, so the full state is genuinely not uniquely
      determined by what we're given. "Clone the RNG" fails here by design.
- On top of that, secret is the very first output and its low 16 bits are never printed
      (everything is >> 16). So we can't read secret off directly either.

The breakthrough was realising we were aiming at the wrong target. We don't need the
19,968-bit state. We need the 8-byte seed, which is only 64 bits. The leaked data
over-determines 64 bits by a mile; the difficulty was never information, it was computing
those 64 bits out of an underdetermined system. Once we have the seed, secret is free: just
re-run Random(seed) and take the first getrandbits(32).


## The piece that makes it solvable

Here's the chain we actually exploited. It has two halves.

Half 1: the state has a known anchor. After seeding, MT always forces state[0] =
0x80000000. That's a free, exact 32-bit constraint we can add to the linear system. It's small,
but it's what collapses the usual truncation ambiguity and makes the solve behave.

Half 2: a band of the state is fully pinned even when the whole state isn't. We built the
full GF(2) system (one variable per state bit, one equation per known leaked bit, plus the
state[0] anchor) and ran Gaussian elimination. The result: the complete state stays
underdetermined (~4,480 free bits, exactly as the counting predicted), but a contiguous run
of state words, roughly indices 229 through 343, comes out completely determined.
No free variables touch them. That band is solid ground.

Why does the band hand us the seed. Random(bytes) doesn't drop the seed into the
state directly. It runs it through CPython's init_by_array, which smears each "key word" (the
seed bytes, chopped into 32-bit words) across the state in a loop. The crucial detail:
init_by_array is periodic. Every key word gets written at many positions, spaced out across
the array, not just once. So even though the seed's "natural" early positions sit in the
undetermined region, the same seed words are also written at later positions, positions that
land inside our determined band. We read the seed key-words out of the band and invert
init_by_array's arithmetic to get the 8 raw seed bytes back.

That's the trick in one line: we can't recover the whole state, so we recover only the handful
of state words that happen to encode the seed, using the fact that MT's seeding writes the
seed into many places.


## How we solved it

We wrote one Python solver (solver.py) that does the maths, and one PowerShell driver
(Solve-Paradise.ps1) that handles the network conversation. The split matters: the seed is
regenerated per connection, so capturing the data and submitting the answer have to
happen on the same socket. You can't solve offline and reconnect.

The solver pipeline:

1. Model MT symbolically. Represent all 19,968 initial-state bits as GF(2) variables,
       then implement the twist and tempering as linear operations over those variables, so
       any output's bits become XOR-expressions in the state. (We validated this model
       bit-for-bit against real random output before trusting it, and that caught a real bug: the
       twist updates the state array in place, so for indices ≥ 227 the feedback term uses
       the already-updated word. Getting that wrong silently corrupts late outputs.)
2. Build and solve the system. Add 16 equations per output (the known top-16 bits of
       each of the 966 values) plus the 32-bit state[0] = 0x80000000 anchor, then
       Gaussian-eliminate over GF(2).
3. Read the determined band. Identify which state words have no dependence on free
       variables (indices roughly 229 to 343) and extract their exact values.
4. Invert init_by_array. Using positions that fall inside that band, recover the seed
       key-words and undo the seeding arithmetic to get the 8 seed bytes. The solver tries
       the handful of valid key-lengths and both the modern (SHA-512-extended) and
       legacy Python seeding schemes, so it doesn't care which Python the server runs.
5. Recover secret and self-check. Re-seed Random(seed), take the first
       getrandbits(32) as secret, then regenerate all 966 truncated values and confirm
       they match the ones the server printed. Only if that check passes do we submit,
       so we never burn an attempt on a wrong answer.

On our local replica this was 30/30 correct, ~0.5s each. Against a faithful mock of the
socket protocol it captured, solved, and pulled the flag end-to-end.

## Setting it off

With both files in one folder, the whole thing is one command in PowerShell:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Solve-Paradise.ps1 -RemoteHost koala.nexsec.my -Port 38310

The driver connects, reads until the first Seed (hex): prompt (which means the something list
has already been printed), scrapes the list with a regex, pipes it to solver.py, then sends
back the recovered seed and secret.

Live run output:

[*] Connecting to koala.nexsec.my:38310 ...
[*] Captured data list (6604 chars). Solving...
[+] Recovered seed = 3b97bd8db0e73255 secret = 3290279278 (kl=18, 0.72s)
---------------- server response ----------------
nexsec26{w0w_y0u_already_kn0w_Mersenne_Twister_nice_19c62e03e755046d40eaa2559
9f5b173110070873073c2209bbd50987b0c9843}

Seed and secret recovered in 0.72 seconds, flag returned on the first submission.


## The flag

nexsec26{w0w_y0u_already_kn0w_Mersenne_Twister_nice_19c62e03e755046d40eaa2559
9f5b17311007087


## Steps to Reproduce

You need Python 3 on PATH (python --version should print 3.x) and the two files solver.py
and Solve-Paradise.ps1 in the same folder. Then, in PowerShell:

# 1. allow the script to run in this window only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# 2. go to the folder holding solver.py and Solve-Paradise.ps1
cd "C:\path\to\Paradise"
# 3. connect, solve, submit, print the flag (one connection, start to finish)
.\Solve-Paradise.ps1 -RemoteHost koala.nexsec.my -Port 38310

The driver prints the recovered seed/secret and then the server's reply, which contains the
flag on success. Our run:

If you ever want to solve by hand instead: connect with nc koala.nexsec.my 38310, copy the
printed list of 966 numbers, run '[...paste list...]' | python solver.py to get {"seed": ..., "secret":
...}, then, in the same nc session, type the seed hex and the secret at the two prompts.


## Why it worked, and the lesson

MT19937's output is linear over GF(2), so truncated outputs are just a (large) system of
linear equations in the state. The challenge's whole defence was handing us less data than
the state is wide, betting that "not enough for full state recovery" means "not enough,
period." It isn't, because the actual secret (the 8-byte seed) is only 64 bits, and MT's
init_by_array seeding is periodic, so the seed is written into many state words. Even when
most of the state is unknown, enough of those seed-bearing words fall inside the solvable
region to reconstruct the seed, and from the seed everything else follows.

Takeaway for next time: when an MT/random challenge gives you truncated or "insufficient"
output, don't fixate on cloning the full state. Count what the real secret is (often the seed,
often tiny), set up the GF(2) system anyway, see which state words come out determined,
and exploit the structure of the seeding routine to pull the secret out of whatever you can
solve for.

## Source Figures

![Original writeup figure](../../assets/paradise/figure-016.png)

![Original writeup figure](../../assets/paradise/figure-017.png)
