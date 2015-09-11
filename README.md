# BTC-wallet-hashchecker

Given a particular encrypted bitcoin wallet and a password attempt, this little program will permute the attempt and test using it to unlock the wallet until it either exhausts the permutation space or succeeds.

build like so:
make -f makefile.hashchecker hashchecker
