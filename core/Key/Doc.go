/*
This package provides interaction with keys. Keys are either private or public keys.
The keys can be exchanged in bundles. The bundles are exchanged during session initialization. 
The sender keeps it's own private bundles while the receiver of the message keeps the sender public bundles.

Private keys are for signing and decrypting messages, while public keys are used 
for verifying and encrypting messages. Both private and public keys are created 
as pairs.

There is a one-time key, both in pairs, called as pre-keys. The bundle contains zero or more pre-keys.
And after being used, they are deleted from the bundle. The pre-keys are stored by it's id.
There is also a signed pre-key, both in pairs of public and private keys.

*/
package Key
