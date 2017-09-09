# Over The Wire - Natas

My solutions to the puzzles at [OverTheWire/Natas](http://overthewire.org/wargames/natas/).

## Levels 0-1

Easy enough, grab the source, get the password.

## Levels 2-3

Again, straight forward starter levels, find the directory, get the password.

## Levels 4-5

Some header manipulation to 'fool' the server into giving the password.

## Level 6

Find the include file in the source and grab the 'secret' key. Post to get password.

## Level 7

Easy enough to alter the request to get the password file.

## Level 8

Check the source to see how the secret is 'encrypted'. Reverse this to get the secret and post to get the password.

## Levels 9-10

Two command injection levels. The second has some character filter, but the first method still works.

## Level 11

XOR obsfucated cookie, so determine the original plaintext and XOR to find the key; use the key on a modified plaintext, get password.

## Level 12

File upload exploit. Nice and simple.

## Level 13

Same as the last, but it checks for an image header. Ok, so just add an image header.

## Level 14

Simple SQL injection.

## Level 15

SQL injection requiring BruteForcing the password. That's an interesting step up from the last one, but I like it.

## Level 16

OK, now we're BruteForcing with a command injection with a much more restrictive character blacklist. A small modification of the last levels code is required.

## Level 17

Very similar to Level 15, but without any text output from the SQL attack. So, time will be our output. Modify the SQL injection to sleep on a match and wait for it.

## Level 18

Now on to BruteForcing an easy to determine session ID.

## Level 19

Same as the last, but the session ID is a little harder to guess.

## Level 20

Abusing a bad serialisation to get us admin.

## Level 21

Using an exploit on one site, to set session variables for another.

## Level 22

Just need to set a param, bit of a step-down in difficulity.

## Level 23

This time the param needs to be a string containing a a certain substring and be a number above 10, so it comes down to how PHP handles string to integer conversions.

## Level 24

Have to find a way around strcmp. Comes to to how it handles non-strings.

## Level 25

A user-supplied param that is used as a filename that is `include`d in the script. Sounds easy, but it's checked for directory traversal, replacing "../" with "". Easy enough to bypass because it doesn't do it in a loop. However, it then checks for a string that would be required to access the password file, killing the script entirely if it detects it. No way around that. But it is doing logging, and writing user supplied information to the log.

## Level 26

PHP serialisation bug. Very interesting. Hadn't considered that as an attack vector before. Of course, I've never considered allowing use input to be deserialised in such a manner before, either.

## Level 27

Timing attack on a database reset.

## Level 28

A little bit of URL mangling to find out it's some Public Key encrypted string. Was thinking I was going to do some form of padding based attack, but it's not CBC, but EBC, which makes the task significantly easier. A little bit of codebreaking shows us that this is an SQL string. So, we just need to find out the block length and the length of the data preceding the user supplied data. Once done we can have the server encrypt our own SQL string, pull it out and send it back alone to get the password.

## Level 29

Perl. Ok. A quick look into the Perl file opening syntax makes me remember why I haven't use perl in almost two decades. Opening files and getting the output from commands can both be done from file opens. It's sheer elegance in its simplicity. It's also terrible for writing safe programs.

## Level 30

Another attack against dynamically typed languages. Similar to Level 24 in the method of the attack, but a deep look into perl `DBI quot`ing to determine how to bypass this particular sanitisation.

## Level 31

Wow. Just, wow. Ok, so a complicated set of circumstances, abusing various Perl 'features' in order to open arbitrary files or, in theory, to execute arbitrary commands, all contained in a BlackHat talk title 'The Perl Jam 2: The Camel Strikes Back'.

## Level 32

On the surface, it looks like the previous attack should work, swapping out the filename for executable commands, abusing perl open syntax, a la Level 29. Doesn't seem to work, however. Not sure if I'm missing a subtlety, of if - and I'm not a fan of suggesting this - the server is configured incorrectly? Given that it was only solved last a little over a month ago, I'm leaning towards the former, but I cannot seem to figure out what I'm doing incorrectly.
