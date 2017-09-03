# Over The Wire - Bandit

My solutions to the puzzles at [OverTheWire/Bandit](http://overthewire.org/wargames/bandit/).

## Levels 0-3

Simple enough, just read the files.

## Levels 4-6

Searching for a file with specified parameters.

## Levels 7-11

Various string manipulations.

## Level 12

A file compressed multiple times, with different methods, and finally hexdumped. Used xxd to reverse the hexdump, and used `file` in a loop to get the mimetype and decompress accordingly.

## Levels 13-15

Password hidden behind various services.

## Level 16

Similar to the last puzzle, but the port isn't known, only that it is in a range with several other services.

## Level 17

More string manipulation.

## Level 18

Probably supposed to be harder, but my setup just bypassed the actual puzzle here.

## Level 19

SUID binary to get password

## Level 20

SUID client binary this time, meaning we need to build a quick-and-dirt server.

## Level 21

Grab the password file out a a script referenced by a cronjob.

## Level 22

Cronjob making a file with an obsfucated name in a directory without execute permissions. Easy enough to recreate the obsfucated name.

## Level 23

A cronjob executing files in a directory. Just need to create a script to copy the password to somewhere we can access it.

## Level 24

Simple brute-force, although complicated a little by a weird timing issue on the pin server.

## Level 25

Interesting solution to this, and recquired a different method in order to be able to send keystrokes instead of commands. Also needed to set the height of the terminal to force `more` to react appropriately.
