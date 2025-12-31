# Forensics

### Pieces of Four
##### Challenge Description
Legends speak of a cursed chest recovered from the depths of the Caribbean.
Every pirate who opens it swears they see something different —
a torn map fragment, a broken sigil, or a piece of a greater truth. - 44442
##### Sol:
After opening the file in Notepad revealed readable text which indicated that the file was not a single image. The file name piece_of_four further suggested that the content was divided into four different parts.

When the file was analyzed using a **hex editor (HxD)**, multiple file headers were found inside the same file. A valid image should contain only one header, but this file contained **several different image headers** at different offsets. These included the JPEG header, PNG header, GIF header , and TIFF header. This header mismatch confirmed that multiple image files were concatenated together, causing header-related issues when viewed normally.

Using the hex editor, the file was split at each header location and saved as separate image files according to their respective formats, all four extracted image fragments were merged in the correct order to reconstruct the full QR code. Once reconstructed, the QR code scanned successfully and revealed the flag.
```
BYPASS_CTF{JPEG_PNG_GIF_TIFF_c0mm0n}
```

### Dead Men Speak NO Plaintext
##### Challenge Description
A network capture was recovered from a ship sailing suspicious waters of the Caribbean.
At first glance, it’s nothing but noisy chatter — routine lookups, failed connections, and meaningless traffic drifting like flotsam.
But legends say that pirates never write their secrets down.  
Flag Format:- BYPASS_CTF{UPPER_CASE}
##### Sol:
The PCAP file was filled with noisy ICMP and UDP traffic as mentioned in the chall's desc as noisy chatter. Looking at the hex data, I saw repeating patterns (`7e 7e`).

After inspecting the hex data of the ICMP and UDP packets, I noticed the payloads contained rhythmic patterns, suggesting a raw data stream was hidden inside. I extracted the raw payloads into a file named `pirate_secret.bin`. To convert this data into a playable format, I used the following **SoX** command:
`sox -t raw -r 8000 -b 8 -c 1 -e unsigned-integer pirate_secret.bin pirate.wav`

- **`-t raw`**: Tells the tool the input has no file header (like a standard WAV or MP3 would).    
- **`-r 8000`**: Sets the **Sample Rate** to 8000Hz (common for low-bitrate voice).
- **`-b 8`**: Sets the **Bit Depth** to 8-bit.
- **`-c 1`**: Sets it to **Mono** (1 channel) instead of Stereo.
- **`-e unsigned-integer`**: Defines the **Encoding**. Since the hex bytes were positive values (00-FF), it had to be unsigned.

After running the command, I opened `pirate.wav` in Audacity. The audio was buried in static, so I used the **Noise Reduction** effect to filter out the background hiss.

Once cleaned, I could clearly hear a voice spelling out the flag: 
```
BYPASS_CTF{V01P_J4CK_1N_TH3_0P3N}
```

# Osint

### Address Unknown
##### Challenge Description
A mysterious cybersecurity blogger has been publishing sensitive reports through the website:decentsecurity.com  
Trace the registration trail and find the street tied to it.
BYPASS_CTF{STREET_NAME_WITHOUT_SPACES}
##### Sol:  
So the challenge required tracing the registration details of the domain **decentsecurity.com**. I used an online WHOIS lookup tool to check the domain’s registration information. The WHOIS record revealed the registrant’s address details, including the street name which was Kalkofnsvegur 2.
```
BYPASS_CTF{Kalkofnsvegur2}
```

### Pelagic Node-14
##### Challenge Description
A submerged visual relay—designated Pelagic Node-14—has been continuously transmitting a live feed from an uncharted mid-ocean depth.  
The camera is fixed, silent, pressure-worn, and linked to a small YouTube livestream that rarely registers more than a handful of viewers.   
Only a single captured frame has been archived for assessment.
The frame contains nothing unusual at first glance—only drifting particulates and the muted gradients of deep water.  
Yet the relay itself operates under an internal classification, a descriptor assigned long before the livestream was ever configured, and long after its manufacturer vanished from public record.
Your objective is simply to determine the descriptor traditionally used for this class of deep-water relay.
Flag format - BYPASS_CTF{city_state_country}
##### Sol:
After analyzing the given frame, it was identified that the image was taken from a YouTube livestream of Aquarium of the Pacific.
[https://www.youtube.com/watch?v=DHUnz4dyb54](https://www.youtube.com/watch?v=DHUnz4dyb54 "https://www.youtube.com/watch?v=DHUnz4dyb54")

This aquarium is located in Long Beach, California, USA.
Most of the time was spent correcting the flag format. Thanks to my teammate.
```
BYPASS_CTF{Long_Beach_California_Usa}
```

### Hidden Hunter
##### Challenge Description
During an inspection of a colonial-era ship registry, investigators found one suspicious entry.  
The individual listed does not appear in any official naval records, yet his description matches that of a notorious pirate long rumored to sail the seas under an assumed identity, .
You have recovered the following excerpt from the ship’s manifest:
Rig: Ship  
Age: 47  
Skin: Dark  
Hair: Brown  
Year: 1800's
Flag format: BYPASS_CTF{Real_Name}
##### Sol:
This chall was too guessy, so I've tried many pirates from this list  
[https://en.wikipedia.org/wiki/List_of_pirates#Post_Golden_Age:_pirates,_privateers,_smugglers,_and_river_pirates:_1730–1885](https://en.wikipedia.org/wiki/List_of_pirates#Post_Golden_Age:_pirates,_privateers,_smugglers,_and_river_pirates:_1730%E2%80%931885) 

then after analyzing i thought i might be some fictional character so gave to chatgpt and after some attempt he gave Josiah Sparrow.
```
BYPASS_CTF{Josiah_Sparrow}
```

### Jellies
##### Challenge Description
A strange image has been recovered from an oceanic research buoy after it briefly connected to an unknown network.  
No metadata survived — only a single frame showing ethereal, floating creatures suspended in blue water.
But something isn’t right.  
The currents in the background flow too smoothly.  
The illumination is too perfect.  
And deep within the fluid shadows, a faint pattern seems to flicker… almost as if the ocean itself is whispering coordinates.
They also suspect there is a hidden pattern hiding in the undulating shapes of the drifting creatures.  
Find out the species of image and the secret code hidden  
Flag Format;- BYPASS_CTF{species_code}
##### Sol:
At first, I tried the image in aperisolve and in the zsteg section i found  
`this_is_a_jelly_H01&01$<stop>`
then i searched online for the jellyfish species name, tried multiple variations, also with google image search and finally this worked.
```
BYPASS_CTF{Sea_Nettles_this_is_a_jelly_H01&01$}
```

### Record
##### Challenge Description
An event without a name is a ghost.  
Bind this account to its rightful record, and in doing so, expose both the number it bears and the waters it disturbed.  
Flag Format:- BYPASS_CTF{portCity_capitalCity_incidentNumber}
##### Sol:
This challenge file gave a morse encoded message. after decoding it, we got something like:
CREW ONBOARD AN ANCHORED TANKER NOTICED TWO UNAUTHORISED PERSONS NEAR THE DECK STORE. MASTER INFORMED GENERAL ALARM RAISED PA ANNOUNCEMENT MADE CREW MUSTERED. SEEFG THE CREW"S ALERTNESS, THE INTRUDERS ESCAPED WITH SHIP'S STORES. INCIDENT REPORTH TO VT DTTMTT WHO DISPATCHED A PATROL BOAT. YOUR TASK IS TO USE THE DESCRIPTIONTO LOCATE THE OFFICIAL INCIDENT NUMBER AND THE LOCATION OF THE INCIDENT.

which described an unauthorized boarding on an anchored tanker.
After decoding the morse text, I researched the incident description and there were many such related incident which happened in bangladesh(I was wrong). But after researching more, i found a very similar description in the IMB piracy report.
https://www.steamshipmutual.com/sites/default/files/medialibrary/files/2025%20-%20Jan%20-%20Sep%20IMB%20Piracy%20and%20Armed%20Robbery%20Report.pdf
From the report, the incident location was Belawan Anchorage and the governing city was Medan.
using the date and vessel details, i checked the IMB PRC map to get the official incident number.
```
BYPASS_CTF{Belawan_Medan_011-25}
```

### Study Partner
##### Sol:
As the name suggests, we have to find the study partner for this CTF.
On linkedin they had posted their partners name which is Hackviser.
```
BYPASS_CTF{Hackviser}
```

### Platform Sp 1
##### Sol:
similarly we get this on their linkedin.
```
BYPASS_CTF{Unstop}
```

### Platform Sp 2
##### Sol:
similarly we get this on their linkedin.
```
BYPASS_CTF{CTF7}
```

### Certificate Partner
##### Sol:
similarly we get this on their linkedin.
```
BYPASS_CTF{Altered_Security}
```

### Snack Sp
##### Sol:
similarly we get this on their linkedin.
```
BYPASS_CTF{Budhani_Bros}
```

# Steg

### Jigsaw Puzzle
##### Challenge Description
A rival pirate ransacked Captain Jack Sparrow's cabin and, in a fit of rage, tore his portrait to shreds. But this was no ordinary portrait. The Captain, in his infinite cunning, had scrawled his latest secret orders across the back of it before it was framed.
The 25 pieces were scattered across the deck. If you can piece the Captain's portrait back together, you might just be able to read his hidden message.
Find the pieces in this directory, reassemble the image, and decipher the orders. Good luck, savvy?
##### Sol:
So in the folder there were around 25 image pieces, each containing some letters, so it was clearly a jigsaw puzzle. i used an online tool to manually merge all the pieces together.

after merging, i got this text:
```
Gurcnffjbeqvf:OLCNFF_PFS{RVTUG_CV_RP_RF_BS_RVTUG}
```

this was ROT13, and after decoding it i got:
```
Thepasswordis:BYPASS_CSF{EIGHT_PI_EC_ES_OF_EIGHT}
```
after fixing some letters, the final flag was:
```
BYPASS_CTF{EIGHT_PIECES_OF_EIGHT}
```

### Gold Challenge
##### Challenge Description
The challenge is contained within the Medallion_of_Cortez.bmp file.
This cursed coin holds more than just gold.
They say the greed of those who plundered it left a stain upon its very soul—a fractured image, visible only to those who can peel back the layers of light.
To lift the curse, you must first reassemble the key. Once the key is whole, its message will grant you the power to unlock the true treasure within. Beware, for the final step is guarded, and only the words revealed by the light will let you pass.
##### Sol:
you just need to upload the bmp file to some online bit plane viewer or use the python script given below to view the different bitplanes and find the QR code in the 0th plane of all 3 RGB colours
```python
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt

IMAGE_PATH = "Medallion_of_Cortez (1).bmp"
SAVE_PLANES = True

img = Image.open(IMAGE_PATH)

# Handle grayscale vs RGB
if img.mode != "L":
    print("Image is color — processing RGB channels.")
    channels = img.split()
    channel_names = ["R", "G", "B"]
else:
    channels = [img.convert("L")]
    channel_names = ["Gray"]

for ch, name in zip(channels, channel_names):

    arr = np.array(ch)

    plt.figure(figsize=(10, 10))
    plt.suptitle(f"Bit Planes — {name} channel", fontsize=14)

    # ORIGINAL IMAGE
    plt.subplot(3, 3, 1)
    plt.imshow(arr, cmap="gray")
    plt.title("Original")
    plt.axis("off")

    # BIT-PLANES
    for bit in range(8):
        plane = ((arr >> bit) & 1) * 255

        plt.subplot(3, 3, bit + 2)
        plt.imshow(plane, cmap="gray")
        plt.title(f"Bit {bit}")
        plt.axis("off")

        if SAVE_PLANES:
            Image.fromarray(plane.astype(np.uint8)).save(
                f"bitplane_{name}_{bit}.bmp"
            )

    plt.tight_layout()
    plt.show()
```
after scanning the QR code, it revealed a **passkey**:  `SunlightRevealsAll` then using this passkey with steghide, i extracted a hidden file `treasure.txt`, which contained the flag.
```
BYPASS_CTF{Aztec_Gold_Curse_Lifted}
```

# Misc
### The Heart Beneath the Hull
##### Challenge Description
Not all treasures are buried in sand,
##### Sol:
The bottom row of the PCB features hexadecimal labels instead of standard pin numbers. By decoding the hex sequence `68 65 61 72 74 5f 69 6e 5f 61 5f 63 68 65 73 74` into ASCII text, you get the flag: heart_in_a_chest
```
BYPASS_CTF{heart_in_a_chest}
```

# Rev
### The Deceiver's Log
##### Challenge Description
"Words are wind, and maps are lies. Only the dead speak true, beneath the tides."
You've found the digital logbook of the infamous Captain "Ghost" Jack. It promises untold riches to those who can unlock it.  
But be warned: The Captain was a known liar. He built this log to mock those who try to steal his secrets.
The program seems... friendly enough. It might even give you a flag.  
But is it the *real* flag?
Trust nothing. Verify everything. The truth is fleeting, existing only for a moment before the lies take over.
Note: The flag format is BYPASS_CTF{...}
##### Sol:
First i ran the binary and it asked for a secret code. using strings i found BYPASS_CTF, and after entering it, the program printed a flag. but since the challenge says don’t trust it, i assumed this flag was fake.

then i opened the binary in gdb and noticed there was an anti-debug ptrace check. when a debugger is detected, a global flag is flipped. because of this, the function that actually generates the flag (whisper_truth) returns bitwise inverted characters instead of the real ones.

I also observed that even during normal execution, the program always prints the fake flag. the real character returned by whisper_truth is overwritten by another function (shout_lies) before it reaches printf.
to confirm this, i placed a breakpoint right after `whisper_truth` returned and inspected the AL register for each call. this gave me signed byte values like -67, -90, etc., which correspond to inverted bytes. 
`189, 166, 175, 190, 172, 172, 160, 188, 171, 185, 132, 171, 141, 138, 202, 139, 160, 177, 207, 160, 207, 145, 204, 160, 177, 207, 139, 160, 186, 137, 204, 145, 160, 166, 207, 138, 141, 160, 186, 134, 204, 140, 130`
after converting them to unsigned values and XORing each byte with 0xFF, i reconstructed the real flag.
Code:
```python
#!/usr/bin/env python3

# initial chaos value
g_chaos = 0x0BADF00D

# XOR constants indexed 0..42
xor_constants = [
    0x4F,0x5F,0x53,0x40,0x53,0xD3,0x9F,0xA3,0xA4,0xBE,
    0x07,0xEA,0xAD,0x1A,0x82,0x2F,0xF2,0x98,0xDB,0x2A,
    0x8A,0x33,0x1D,0x48,0x45,0xB5,0x36,0xFE,0x95,0x1E,
    0x07,0x74,0x52,0x5F,0x33,0x74,0x72,0xDF,0x85,0x99,
    0xC3,0x8B,0x01
]

def ror32(val, n):
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

def solve():
    temp = g_chaos
    out = []

    for i in range(len(xor_constants)):
        ch = temp ^ xor_constants[i]
        out.append(ch & 0xFF)   # single byte
        temp = ror32(temp, 1)

    print(bytes(out).decode())

if __name__ == "__main__":
    solve()
```

```
BYPASS_CTF{Tru5t_N0_0n3_N0t_Ev3n_Y0ur_Ey3s}
```

### The Cursed Compass
##### Challenge Description
"The seas are rough, and the Kraken awaits."
We've recovered a strange game from a derelict pirate ship. The captain claimed the game held the coordinates to his greatest treasure.  
But every time we win, the treasure seems... fake.
Can you navigate the treacherous code and find what lies beneath the surface?  
The game is built for Linux (x86_64). You might need to install SDL2 to run it (`sudo apt install libsdl2-2.0-0` or similar).
Hint: Sometimes, the waves themselves whisper the secrets.
Note: The flag format is BYPASS_CTF{...}
##### Sol:
first i checked the file using file and strings. the binary is a 64-bit linux ELF and strings directly showed a flag-looking string:
`BYPASS_CTF{Y0u_S4il3d_Th3_S3v3n_S34s_But_M1ss3d_Th3_Tr34sur3}`  
but the challenge description clearly hinted that the treasure is fake, so i treated this as a decoy. then i ran the game. after winning, the game always prints the same flag, confirming it is hardcoded and fake. so the real logic had to be somewhere else.

i opened the binary in ghidra. since it is not stripped, function names were visible. inside the render loop (render_game), i noticed a strange function call named `calculate_wave_physics`. this function was being called every frame, even though it had nothing to do with graphics.

after reversing `calculate_wave_physics`, i found it was not physics at all. it takes an index, generates a value using a linear congruential generator (LCG), shifts it, and XORs it with a byte from a global array `g_tide_data`. this is basically a custom decryption routine hidden inside rendering logic (matching the hint: *waves whisper the secrets*).

i extracted the encrypted bytes from `g_tide_data` and recreated the logic in python.

Code:
```python
seed = 195948557
data = [
0x4F,0x5D,0x21,0x4E,0x0A,0x5E,0x98,0x0D,0xFE,0xEA,
0xB2,0xB0,0xC8,0x57,0x9E,0xE8,0xB8,0x49,0x84,0x5C,
0xCE,0x7E,0x49,0xEA,0xEF,0x6F,0x16,0xE3,0x8A,0x29,
0x70,0x44,0x83,0xA5,0x39,0x67
]

def calc(index):
    s = seed
    for _ in range(index):
        s = (1664525 * s + 1013904223) & 0xffffffff
    return ((s >> (index % 7)) & 0xff) ^ data[index]

flag = ''.join(chr(calc(i)) for i in range(len(data)))
print(flag)
```

```
BYPASS_CTF{Fr4m3_By_Fr4m3_D3c3pt10n}
```

### Dead Man's Riddle
##### Challenge Description
"Ye who seek the treasure must pay the price... Navigate the chaos, roll the dice."
A spectral chest sits before you, guarded by a cursed lock that shifts with the tides. The local pirates say the lock has a mind of its own, remembering every mistake you make. There are no keys, only a passphrase spoken into the void.
Can you break the curse and claim the flag?
Note: The flag format is BYPASS_CTF{...}
##### Sol:
Did same for this, used strings and file commands. It was a 64-bit linux ELF and `strings` shows a flag-like string, but based on the description it is clearly a fake flag. so the real flag is validated through logic. From `main`, i saw that the input length must be exactly 30 characters. each character is processed one by one using a function pointer (`consult_compass`) and then verified using `check_course`. if anything fails, the program exits.

There is a global variable `g_state` initialized as `0xdeadbeef`. before `main`, an init function (`init_map`) modifies this state using XOR and bit rotation. this means the initial state is predictable and reversible. Inside `consult_compass`, each character depends on the current `g_state`. a byte is extracted from `g_state` using a shift based on index, then XORed with `(char + index)`. after that, `g_state` is updated again using a multiplication and addition. so the check is **stateful**, meaning every character affects the next one.
`check_course` simply compares the transformed value with a hardcoded expected value for each index (0–29).
`0x12,0x53,0x3c,0x44,0x20,0x77,0xa8,0xe8,0x52,0x31, 0xeb,0x93,0x38,0x28,0x6f,0x67,0x5f,0x2e,0xc8,0xde, 0x74,0xe0,0x79,0xb9,0x48,0x54,0xf1,0x80,0xcb,0x58`
so the solution is to recreate the logic and brute-force each character sequentially while updating `g_state`.

Code:
```python
# Reverse solver for the compass challenge

TARGET = {
    0: 18,
    1: 83,
    2: 60,
    3: 68,
    4: 32,
    5: 119,
    6: 168,
    7: 232,
    8: 82,
    9: 49,
    10: 235,
    11: 147,
    12: 56,
    13: 40,
    14: 111,
    15: 103,
    16: 95,
    17: 46,
    18: 200,
    19: 222,
    20: 116,
    21: 224,
    22: 121,
    23: 185,
    24: 72,
    25: 84,
    26: 241,
    27: 128,
    28: 203,
    29: 88,
}

def consult_compass(c, pos, g_state):
    transformed = ((g_state >> (pos % 5)) & 0xFF) ^ (c + pos)
    g_state = (31337 * g_state + c) & 0xFFFFFFFF
    return transformed, g_state


def solve(initial_state):
    g_state = initial_state
    out = []

    for pos in range(30):
        target = TARGET[pos]

        # brute-force printable characters
        for c in range(32, 127):
            transformed = ((g_state >> (pos % 5)) & 0xFF) ^ (c + pos)
            if transformed == target:
                out.append(chr(c))
                g_state = (31337 * g_state + c) & 0xFFFFFFFF
                break
        else:
            raise ValueError(f"No match at pos {pos}")

    return "".join(out)


if __name__ == "__main__":
    flag = solve(initial_state=336)
    print(flag)
```

```
BYPASS_CTF{T1d3s_0f_D3c3pt10n}
```

### The Captain's Sextant
##### Challenge Description
"The stars guide the way, but only for those who know the rhythm of the ocean."
You have found an old navigational simulator used by the Pirate Lord to train his navigators.  
Legend says the Lord hid the coordinates to his stash inside the simulation itself.  
But it only reveals itself to those with perfect intuition.
Align the sextant. Follow the stars.  
But remember: The game knows when you are guessing.
Note: The flag format is BYPASS_CTF{...}
##### Sol:
So this was a reverse challenge with a game. When you play and win, it shows a fake flag, so that was clearly a trap. I opened the binary in Ghidra and looked for functions that were not related to graphics or input. I found a function called `align_star()` which looked suspicious because it was doing PRNG math and XOR, typical flag logic.

This function was called every time a key was pressed, using an `input_count` as index. The index was modulo **44**, so that told me the flag length is **44 characters**. There was also a static array `g_star_timings[44]` used as a key. The gameplay timing and “intuition” stuff was just a red herring the real flag bytes were never printed.

So I copied the logic of `align_star()` and the `g_star_timings` array into a Python script and generated each character offline.
```python
# Recreate align_star & keystream-based decryption
# Fill in `cipher` with the encrypted bytes

g_star_timings = [
    0xE5,0xF3,0x6F,0x7F,0x10,0x33,0xA1,0x24,0xCB,0x30,
    0xD6,0xFD,0x8A,0x81,0x7D,0xEC,0xF0,0x9D,0xEA,0x07,
    0x6C,0xBD,0x2C,0xCE,0xFD,0xF7,0xBD,0xF7,0x9A,0xEA,
    0x4F,0x87,0xCE,0xB4,0x28,0x7E,0x4B,0xA3,0xE9,0x45,
    0x4F,0x97,0x81,0x68
]

# --- REPLACE THIS WITH YOUR CIPHERTEXT BYTES ---
cipher = g_star_timings[:]   # if timing values *are* ciphertext
# cipher = [ ... ]           # otherwise paste here
# -----------------------------------------------

k = 322416807
plain = []

for i in range(len(cipher)):
    # advance RNG i times total
    if i > 0:
        k = (1103515245 * k + 12345) & 0x7FFFFFFF

    ks = (k >> (i & 3)) & 0xFF   # keystream byte
    p = cipher[i] ^ ks           # decrypt
    plain.append(p)

print("Decrypted bytes:", plain)
print("As text:", ''.join(chr(x) for x in plain))
```

Running the script directly gave the real flag.
```
BYPASS_CTF{T1m1ng_1s_Ev3ryth1ng_In_Th3_V01d}
```

# Web
### Pirate's Hidden Cove
##### Challenge Description
You've discovered a secret pirate cove, hidden deep within the Tor network — a place where digital buccaneers stash their treasures. Somewhere on these sites lies the captain's flag. Can you find the 📄.
##### Sol:
The challenge provided a Tor hidden service URL, which hinted that the flag was hosted somewhere inside the Tor network. The given onion link was:
`http://sjvsa2qdemto3sgcf2s76fbxup5fxqkt6tmgslzgj2qsuxeafbqnicyd.onion/`

I accessed the site using the Tor Browser, but the page appeared empty and did not show anything useful. Since nothing was visible on the main page, I suspected that the flag might be hidden in an undisclosed directory.
Because the target was an `.onion` service, normal directory brute‑forcing would not work without routing traffic through Tor. I researched how directory enumeration works on Tor hidden services and took reference from the following article:
**Reference used:**  [https://viking71.medium.com/subdomain-enumeration-of-onion-sites-5dd3c7f9e4ae](https://viking71.medium.com/subdomain-enumeration-of-onion-sites-5dd3c7f9e4ae)
(due to some issues, i used dirsearch)
Based on this, I set up Tor on WSL and ensured the Tor service was running locally on port `9050`. Instead of using proxychains, I directly configured the tool to use a SOCKS5 Tor proxy.
I then used `dirsearch` with a low thread count and higher timeout to avoid overwhelming the onion service.

Command used:
```bash
dirsearch -u http://sjvsa2qdemto3sgcf2s76fbxup5fxqkt6tmgslzgj2qsuxeafbqnicyd.onion/ \
-w common.txt \
--proxy socks5h://127.0.0.1:9050 \
-t 1 \
--timeout 15
```
During enumeration, I discovered a `.env`. When I visited the `.env` path in the browser, the file was downloaded directly. After opening .env we got this flag:
```
BYPASS_CTF{T0r_r0ut314}
```