# pwman

**Note**: This is a fork of the [original pwman](http://pwman.sf.net/),
maintained mostly for Torchbox internal use.  It may be useful to other people,
but proceed at your own risk.

PWMan is a password manager which uses gpg encryption to safeguard your data.
It provides a simple and easy to use command line (NCurses) interface to 
manage, store, search and retrieve your passwords.

The look and feel is based on Jaakko Heinonen's abook.

## Installation

Building pwman requires:

- A C compiler (tested with Clang and GCC)
- ncurses (http://www.gnu.org/software/ncurses/)
- libxml2 (http://www.xmlsoft.org/)
- GnuPG 1.x (http://www.gnupg.org/)

For example, on Debian:

    # apt-get install libncurses-dev libxml2-dev gcc make gnupg

To build:

    % ./configure
    % make

To install, as root:

    # make install

You can also uninstall later:

    # make uninstall

## Before using pwman

Before you can run pwman, you will need to generate a GPG key if you don't 
already have one:

    % gpg --gen-key

For more information, see the gpg manual page, or the GPG
[mini-howto](http://www.dewinter.com/gnupg_howto/english/GPGMiniHowto.html).

## Setup

When you first run pwman, it will prompt you for several things:

* GPG key ID: the id of the gpg key you want to use to encrypt the
  database.  Run 'gpg -K' to see a list of available keys; the key
  id is an 8-digit hex number, e.g. 2B9CE6F2.

* Path to gpg: this will most likely be /usr/bin/gpg (Debian),
  /usr/local/bin/gpg (BSD) or /opt/local/bin/gpg (MacPorts).

* Password database file: where to store the encrypted database.
  Most people can accept the default here.

* Passphrase timeout: how long to wait until requiring the user to
  re-enter the gpg passphrase.  This is a security feature.

These configuration settings will be written to your home directory. You can
change them at any time by running pwman, and pressing 'o' at any time.

## Upgrade

Currently, all versions of pwman use the same encryption scheme (gpg) and
the same XML format. As such, to upgrade, simply drop in the new binary.

## Getting help

Once pwman is running, and you have entered your (GnuPG) passphrase, you can
hit '?' to get up the program help. This will tell you what all the keys are
to perform actions in pwman.
 
## License

All files in this distribution are released under the GNU GENERAL PUBLIC 
LICENSE.  See COPYING FOR DETAILS.

## Contact

Send bugreports, fixes, wishes etc. to Felicity Tarnell <felicity@loreley.flyingparchment.org.uk>.
