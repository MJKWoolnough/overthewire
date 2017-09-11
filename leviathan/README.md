# Over The Wire - Leviathan

My solutions to the puzzles at [OverTheWire/Leviathan](http://overthewire.org/wargames/leviathan/).

## Level 0

Easy starter, grep the file.

## Level 1

Initially used `strings` to try and find the password, which did not work. Secondly, used `vim` to just scan the file manually, which did work, but wasn't particularly satisfactory, or automatable. So, `ltrace` to the rescue, which works wonderfully.

## Level 2

`ltrace` being used again to follow the logic of the program, which reveals a flaw in the how it uses the command line parameter, which we can use to do our bidding.

## Level 3

Almost identical to Level 1. Same solution.

## Level 4

`bin2asc`, easy.

## Level 5

setuid binary `cat`ing a non-existant file. Let's make it exist then.

## Level 6

A brute force problem extremely similar to Bandit 24, although a little easier due to the lack of a timing issue.

