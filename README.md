# BTC-wallet-hashchecker

Given a particular encrypted bitcoin wallet and a password attempt, this little program will permute the attempt and test using it to unlock the wallet until it either exhausts the permutation space or succeeds.

https://github.com/jakeva/bitcoin-pwcheck is a similar project, forked from the bitcoin-core source. It has a lot of dependencies and code that is simply unnecessary for the job of rapidly testing passwords against a bitcoin wallet encryption scheme. Another difference is that it is possible to pipe input to it, in order to allow testing, for instance, a dictionary of possible passwords as opposed to permuting one. The same approach could be taken in this project, but for now it is configured only for permuting a password guess.

build like so:
make -f makefile.hashchecker hashchecker
