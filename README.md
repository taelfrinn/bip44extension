
Bip 44 extensions
=================

### Abstract

This proposal extends the structure of BIP 44 with additional conventions for
the use of bip32 key paths. 


### Motivation

Compatibility via standardization allows users a choice of bitcoin wallet
software, and the ability to bring all the features and received coins
along with them, without the need to sweep and to communicate new addresses
to all trading partners. Additionally users will be able to port their
mnemonics to new hardware platforms as needed.

Additionally, BIP32 and related standards allow a user to control a large set of key material
using only a small easy to memorize mnemonic phrase. Simple wallet keys
are only one application. 

If standardized, hardware wallets could be exteneded to provide these 
additional features. For example, a hardware wallet could also serve as
an identity management vault with PEM certificate challenge/response, or a secure
communications vault by creating gpg signature packets.

### Bip44 baseline

Bip44, specifically for bitcoin, currently defines the paths:

* m/44h/0h/*account*h/0/*n* as external key *n*
* m/44h/0h/*account*h/1/*n* as change key *n*

### Proposed Extensions

* Printable Cash
* Exportable Payment Books
* Publishable Stealthcoin roots
* Deterministic GPG keys

####  Printable Cash

Printing BIP38 style cash with QR codes using external or change 
keys puts an entire account at risk, because a single private key can be used to
compute all possible external and change private keys. Using randomly generated
private keys requires separate backup methodologies, or the risk of loss of fund
due to destruction or loss of the paper cash. The ability to sweep or recover lost
paper cash using a bip39 mnemonic improves utility. Using a hardened path
within a hd wallet limits the exposure cause by cash printing and trading. Having
a convention for cash paths allows wallet software to track unspent cash belonging
to a wallet.

####  Exportable Payment Books

Many wallet support tracking an address book for payment destinations. Typically these
are single addresses, which encourages the bad practice of address re-use. As an
alternative a xpub could allow a meaningful address book for multiple payments, as each
payment could comprise a new, never before used destination address. In order to prevent
inadvertent address re-use, a payment book should ideally represent a relationship from
a single hd wallet to another single hd wallet, in some cases for a single purpose. The same address
book should not be shared with multiple different other users. 

In order to create "payment books" for the purpose of giving to other users, and to help
prevent re-use of the payment book, the wallet could have a convention path for such generation.
The wallet would also be able to automatically detect received payments on defined payment books.

####  Publishable Stealthcoin roots

Multiple stealthcoin system exist in the wild, and they typically require the publishing of
a bitcoin public key. A wallet with a convention for generating such stealthcoin roots would
allow for automatic inclusion of received stealthcoins.


####  Deterministic GPG keys

While a bitcoin wallet can be recovered from a mnemonic, GPG private keys do not offer such
functionality. Most bitcoin wallets offer message signing, but few offer comparable 
message encryption to gpg. Starting with gnuPG version 2.1 t is possible to create a GPG private
key using the bitcoin curve secp256k1.

GPG key encoding typically requires entropy, and time values presumably set from the current time.
If a GPG is regenerated from a wallet, this will invalidate signatures, may change key ID's, and
otherwise cause problems for normal GPG usage. This proposal will describe a fully deterministic 
GPG key creation convention, such that GPG keys can be recovered fully from only a mnemonic multiple
times while outputting bit for bit identical output, which will allow any external key id's and
signatures to remain valid.

### Proposal Specifics

In general, each of the proposals extend the bip44 path for a given account by using a 
hardened derived key in the external/change position, instead of a 0 or 1.

#### Printable Cash (2H)

Each cash note created by the wallet for account *acct* will have an ordinal number *ord*, starting from 0

The wallet will create them using this path: 
	44H/0H/*acct*H/2H/*ord*H

The wallet should track any coins that arrive in defined cash key ordinals.

#### Exportable Payment Books (3H)

Each payment book created by the wallet for account *acct* will have an ordinal number *ord*, starting from 0.
The wallet should allow the user to designate the recipent and purpose of the payment book. The wallet should
also track any payments recieved into a payment book address.
			
The wallet will create them using this path: 
	44H/0H/*acct*H/3H/*ord*H

#### Publishable Stealthcoin roots (4H)

Each stealthcoin root created by the wallet for account *acct* will have an 
ordinal number *ord*, starting from 0. The wallet should also track any 
payments recieved into stealth root using the stealth scheme's usual  mechanism

The wallet will create them using this path: 
	44H/0H/*acct*H/4H/*ord*H

#### Deterministic GPG keys (6H)

GPG keys are structured in packets according to RFC 4880 and 6637. The current time will be ignored
, and all time values will be set to 0x495C0780 aka 1230768000, representing the 1st of jan 2009 UTC.
To replace entropy in ECDSA signatures, RFC6979 deterministic signatures will be used. For the
public portion of the keys, no external entropy is used besides what comes from the HD wallet itself. 
When exporting s2k protected private keys, external entropy may be used, as the s2k portion
of the secret key does not need to be invariant - as it does not affect the key ID, nor do signatures
of the keys depend on the secret s2k protected portions.

When exporting only public keys, the first seven packets of output in order will be:

* cert key (tag 6)
* cert key signature (tag 2)
* user id (tag 13)
* encryption subkey (tag 14)
* encryption subkey signature (tag 2)
* signing subkey (tag 14)
* signing subkey signature packet (tag 2)

When exporting secret keys, the first seven packets of output in order will be:

* cert key (tag 5)
* cert key signature (tag 2)
* user id (tag 13)
* encryption subkey (tag 7)
* encryption subkey signature (tag 2)
* signing subkey (tag 7)
* signing subkey signature packet (tag 2)

All key and subkey packets will use secret key values determined by the following BIP32 paths.
(chain code information is not encoded into GPGP packets)

For a given HD wallet account *acct*, there will exist a single unique certifying key,
which will not be classified for creating signatures, nor as an encryption destination.

The certifying key will be at this path for account *acct*:
			44H/0H/*acct*H/6H

Each certifying key will have at least one encryption destination subkey, to be used for
ECDH encryption and decryption. 

The first encryption subkey will be at this path for account *acct*:
			44H/0H/*acct*H/6H/0H

Multiple encryption subkeys may be created, at any even hardened index after 0H

Each certifying key will have at least one signing subkey, to be used for
ECDSA signatures. 

The first signing subkey will be at this path for account *acct*:
			44H/0H/*acct*H/6H/1H

Multiple signing subkeys may be created, at any odd hardened index after 1H.

When exporting a series of GPG packets representing a GPG public or secret key packet, the
following options will be used.

Naturally, public key algorithm 18 and 19 must be used, with the secp256k1 curve, encoded OID of 0x052b8104000a.
As required, all public keys will be uncompressed. Only when exporting ECDH keys, the key flags used
will be 0x03010807, signifiying that sha256 with AES 128 is used for gpg KDF and key wrapping.

the user id packet will use the first 5 words or the bip39 mnemonic encoded raw hash160 compressed address of 
the cert key. AKA bip39mnemencode( RIPEMD( SHA256( compressed-pubkey-of(44H/0H/*acct*H/6H)) ) ).truncate(first 5)

All secret key packets should use s2k. Any s2k method may be used. Method 3, "Iterated and Salted S2K", is recommended.

All signature packets will use RFC 6979 deterministic signatures. The cert key signature packet (tag2)
will be of type 0x13 "Positive certification of a User ID and Public-Key packet". The public algorithm
will of course be of type 0x13 ECDSA. The Hash algorithm must be of type 0x08 SHA256. The hashed
subpackets will be:

* "creation time" 0x02 of 0x495C0780. 
* "Key Flags" 0x1B of value (0x01)  cert only 
* "Preferred Symmetric Algorithms"  0x0B of 0x090807 indicating AES256, AES192, and AES 128
* "Preferred Hash Algorithms" 0x15 of values 0x08090A03 indicating SHA256, SHA384, SHA512, and RIPE-MD
* "Preferred Compression Algorithms" (0x16) of values 0x020301 indicating zlib, bzip, zip

the unhashed pubpackets will be:

* "Issuer" 0x10 with the fingerprint of the cert public key computed as per rfc4880

Sukey signature packets (tag 2 also) will be of type 0x18 "subkey binding signature".
The hash algorithm will also be 0x08 SHA256. The hashed subpackets will be:

* "creation time" 0x02 of 0x495C0780. 
* "Key Flags" 0x1B of value (0x02) for a singing subkey and 0x0C for an encryption subkey

The unhased subpackets will be:

* "Issuer" 0x10 with the fingerprint of the cert public key computed as per rfc4880

In the case of a sub-signing key packet, additionally 

* "Embedded Signature" 0x20, value computed as per rfc4880

### Unit Test

#### GPG public key unit test

* Mnemonic = 'runway smart water canyon illness system west sing woman once receive harsh'
* No extra passphrase
* Account number: 45
* cert key is at m/44H/0H/45H/6H = KygjLd4fy6DLZh5QujADMNBMmdorKy39UXELzE6X8PtCMdtzhHDu 
* encrypting subkey @ m/44h/0h/45h/6h/0h = Kzt9SMacQg4JneVnpaBWidogNJ6efy6gnXQYWN5iqcZrX6J6tGWd 
* signing subkey @ m/44h/0h/45h/6h/1h = L5Lv3SP3XGgDVsvUWfnXbgHUPYT34UhPVbP497fKERdwHEYBN2gk

    -----BEGIN PGP PUBLIC KEY BLOCK-----
    
    mE8ESVwHgBMFK4EEAAoCAwRkZIqXqA5M0+ga0cy7c95jiANy+vuAmeLWNd/VEYUa2zpq7BDBknG8
    JjnIotlm0wSIM5wfmdSfBC5WMSFTwy7FtCNmYWN1bHR5IHN1cHJlbWUgb3RoZXIgcmViZWwgcHJv
    dGVjdIhxBBMTCAAZBQJJXAeAAhsBBAsJCAcFFQgJCgMEFgIDAQAKCRARgR9OITlbN0XMAQDUv6JC
    Yz0Oh37PAXSbpylSrfngs/XBqfo0w7xF5W1vjgD/QKtyqNqFqfqn5WaPdjCDgXzBAWIgk0wPQmjq
    +sWsgwW4UwRJXAeAEgUrgQQACgIDBMUHnrF7IyfX06q2L/nHI6cnTZM9TCTDsgcadYA2jh/HHkBj
    2aV4+P/gKW+8w01RPLUd1H5P3novV2KrN/16OMMDAQgHiGEEGBMIAAkFAklcB4ACGwwACgkQEYEf
    TiE5WzfIewD9Hf5d95R54obyH+RlfUDyWIwRWdZ9ctumwlIAHXmM6YgA/186ZbEJAZxg9umRsgd0
    nQvv+dwKSIcUtWhytbiW1ykpuE8ESVwHgBMFK4EEAAoCAwTsvqcxGhIBS3KtIpAGYQQsrAaDAmWg
    86BPN6RrrR+9bVh9sOk5ljugKdyVdpbhYjB+GmQh2Udk35+INJskljtYiMEEGBMIAAkFAklcB4AC
    GwIAagkQEYEfTiE5WzdfIAQZEwgABgUCSVwHgAAKCRDOt/H8tcYNaAnOAP4yLY1/CYI7dfh0cByR
    jD7LO5OlfPiG4lsMDdRjn4t/uwEAvkHMtqCXjVpg11mXCRDFk2ZVIZSMvnV3gwIbucK0nEuJ1QD9
    EM3Yv/Knp3y2p77rUxn0CUWAbNjEs4IVCejOdQIu504BAOGINmi7D84lv9omgjoyKJLwpSI5b60p
    61E2qV8PbZGx
    =n8Zs
    -----END PGP PUBLIC KEY BLOCK-----


