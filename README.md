# build-NDecrypt-keys

A tool to help generate the necessary `keys.bin` for NDecrypt (
https://github.com/SabreTools/NDecrypt).

***NOTE: You must find the keys elsewhere. They will not be provided.***

```
usage: main.py [-h] [--verbose] [--outpath OUTPATH] [--aeskeydb_bin AESKEYDB]
               [--aes_keys_txt AESKEYSTXT]
               [--hardware_constant HARDWARE_CONSTANT] [--KeyX0x2C KEYX0X2C]
               [--DevKeyX0x2C DEVKEYX0X2C]

Generate NDecrypt keys.bin from Godmode9's aeskeys.bin or Citra's aes_keys.txt
Checks that the correct keys have been loaded via hash. Note: If you have the
standard aeskeydb.bin (sha256
4076543DA3FF911CE1CC4EC72F92E4B72B240015BE9BFCDE7FED951DD5AB2DCB)then you will
need to additionally find generator, KeyX0x2C, and DevKeyX0x2C and supply them
via arguments --hardware_constant, --KeyX0x2C, and --DevKeyX0x2C,
respectively.

optional arguments:
  -h, --help            show this help message and exit
  --verbose             Print all debug messages
  --outpath OUTPATH     Path for the keys.bin. If not supplied, will output in
                        the same directory as aeskeydb.bin / aes_keys.txt
  --aeskeydb_bin AESKEYDB
                        Path for the aeskeydb.bin
  --aes_keys_txt AESKEYSTXT
                        Path for the aes_keys.txt
  --hardware_constant HARDWARE_CONSTANT
                        Hardware constant value (big endian), also referred to
                        as 'generator'. Not contained in standard
                        aeskeydb.bin. If not supplied, will fill with 0s
  --KeyX0x2C KEYX0X2C   KeyX0x2C value (big endian). Not contained in standard
                        aeskeydb.bin. If not supplied, will fill with 0s
  --DevKeyX0x2C DEVKEYX0X2C
                        DevKeyX0x2C value (big endian). Not contained in
                        standard aeskeydb.bin. If not supplied, will fill with
                        0s
```

**Examples:**

Run with aeskeydb.bin:

```
python main.py --aeskeydb_bin aeskeydb.bin --hardware_constant 0123456789ABCDEF0123456789ABCDEF --KeyX0x2C 0123456789ABCDEF0123456789ABCDEF --DevKeyX0x2C 0123456789ABCDEF0123456789ABCDEF
```

Run with aes_keys.txt:

```
python main.py --aes_keys_txt aes_keys.txt
```

If you're missing any keys, the script will let you know:
```
$ python main.py --aeskeydb_bin aeskeydb.bin
[WARNING] Key Hardware constant not found. Filling with zeroes...
Writing key 'KeyX0x18' to keys.bin...
Writing key 'KeyX0x1B' to keys.bin...
Writing key 'KeyX0x25' to keys.bin...
[WARNING] Key KeyX0x2C not found. Filling with zeroes...
Writing key 'DevKeyX0x18' to keys.bin...
Writing key 'DevKeyX0x1B' to keys.bin...
Writing key 'DevKeyX0x25' to keys.bin...
[WARNING] Key DevKeyX0x2C not found. Filling with zeroes...
```

Hashes for the complete `keys.bin`:
```
CRC32:    A112F739
MD5:      1FCE33E354450D0015AD5AE343DBC54D
SHA-1:    13CD8E503C2F6396128CB288B36B223782EE1A12
SHA-256:  9E313734F41A9C83C5477333CA9CCE4B6EA35E56E8A97088828BD3978CE64DCA
```
