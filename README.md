JEDI Protocol Implementation
============================

This repository implements the JEDI protocol described in our paper:

Sam Kumar, Yuncong Hu, Michael P Andersen, Raluca Ada Popa, and David E. Culler. **JEDI: Many-to-Many End-to-End Encryption and Key Delegation for IoT.** 28th USENIX Security Symposium. August 2019.

This is *not* the JEDI implementation for bw2 used for the paper's benchmarks in Section 7.2. That implementation is available at http://github.com/ucbrise/jedi-protocol. This implementation is the one we plan on using in IoT deployments (e.g., the XBOS project). Our main reason for writing this implementation separately from our previous prototype is that the bw2 system, which was in use at the time we originally developed JEDI, has now been supplanted by WAVE version 3. While WAVE itself only builds on the authorization functionality in bw2, the WAVEMQ system, which uses WAVEv3, implements a syndication tier similar to bw2's. Given that bw2's users are migrating to WAVEv3 and WAVEMQ, we needed to produce a new JEDI implementation that was not as closely tied to one particular syndication system. That "new JEDI implementation" is in this repository.

Although this implementation of JEDI is, in many ways, starting from a clean slate, it reuses code from the previous JEDI implementation for bw2 in the following ways:

* Much of the code in the previous implementation, particularly that in the `core` package, is reused in this one.
* Both the old implementation and this one depend on the JEDI Cryptography library for JEDI's assembly-optimized cryptography routines. That library can be found at http://github.com/ucbrise/jedi-pairing.

For the code that was formerly in the `core` package of the JEDI implementation for bw2, we opted to copy the code to use in this implementation rather than depending on the old repository. This allows the code to evolve without disturbing our old implementation for bw2, which remains useful as an artifact for those wishing to reproduce our evaluation results from Section 7.2 in the JEDI academic paper (see citation above).

What is JEDI?
-------------
JEDI is an end-to-end encryption protocol for *decoupled, many-to-many* communication. One example of such communication is the publish-subscribe paradigm. In publish-subscribe systems, the sender of a message does not know who will receive the message. The sender labels the message with a *topic* (sometimes called a *resource*), and an intermediate *broker service* is responsible for forwarding the message to those interested in that topic.

In such settings, traditional end-to-end protocols, like SSL/TLS, do not directly apply. These protocols typically require the sender of a message to encrypt it using the recipient's public key, but this is impossible in decoupled, many-to-many communication because the sender doesn't know who the recipients are.

JEDI allows the sender to encrypt messages in such a way that only those who are authorized to receive messages for the relevant topic to decrypt the message. We designed JEDI with IoT-oriented publish-subscribe use cases in mind, so it supports fine-grained expiry, hierarchically-structured topics, and decentralized delegation. The intermediate broker does not participate at all in the JEDI protocol, so it applies generally to *decoupled, many-to-many* communication (e.g., multicast), not just publish-subscribe.

The acronym **JEDI** stands for **J**oining **E**ncryption and **D**elegation for **I**oT.

License
-------
The code in this repository is open-source under the BSD 3-Clause License.
