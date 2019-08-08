JEDI Protocol Implementation
============================

This repository implements the JEDI protocol described in our paper:

Sam Kumar, Yuncong Hu, Michael P Andersen, Raluca Ada Popa, and David E. Culler. **JEDI: Many-to-Many End-to-End Encryption and Key Delegation for IoT.** 28th USENIX Security Symposium. August 2019.

This implementation of JEDI is a library that implements the JEDI protocol for end-to-end encryption. It is written to be mostly independent from the underlying system used to transport messages. It is meant to be used by a messaging system to encrypt/decrypt messages and delegate keys, by making API calls to this JEDI library. We have integrated JEDI into WAVEMQ, a publish-subscribe system that uses WAVE for authorization, in this manner. The WAVEMQ service, responsible for sending/receiving messages, makes API calls to JEDI to encrypt/decrypt messages. WAVE, the authorization sytem used by WAVEMQ, makes API calls to JEDI to include keys in its attestations for delegation. The code for that integration is available in the GitHub repositories for WAVE and WAVEMQ, at https://github.com/immesys/wave and https://github.com/immesys/wavemq, respectively.

Our original JEDI implementation was tied closely to bw2, the predecessor to WAVE. As bw2 fell out of use and was supplanted by WAVE and WAVEMQ, we found it necessary to overhaul our original implementation so that it is not closely tied to the underlying syndication system. If you are interested in our original implementation (for example, to reproduce our results from Section 7.2 of the paper), then please contact us.

JEDI's new WKD-IBE encryption algorithm, assembly-optimized for Cortex-M0+, x86-64, and ARMv8 platforms, is not in this repository. It is available at http://github.com/ucbrise/jedi-pairing. Our implementation of JEDI in this repository uses that code as a black box.

What is JEDI?
-------------
JEDI is an end-to-end encryption protocol for *decoupled, many-to-many* communication. One example of such communication is the publish-subscribe paradigm. In publish-subscribe systems, the sender of a message does not know who will receive the message. The sender labels the message with a *topic* (sometimes called a *resource*), and an intermediate *broker service* is responsible for forwarding the message to those interested in that topic.

In such settings, traditional end-to-end protocols, like SSL/TLS, do not directly apply. These protocols typically require the sender of a message to encrypt it using the recipient's public key, but this is impossible in decoupled, many-to-many communication because the sender doesn't know who the recipients are.

JEDI allows the sender to encrypt messages in such a way that only those who are authorized to receive messages for the relevant topic to decrypt the message. We designed JEDI with IoT-oriented publish-subscribe use cases in mind, so it supports fine-grained expiry, hierarchically-structured topics, and decentralized delegation. The intermediate broker does not participate at all in the JEDI protocol, so it applies generally to *decoupled, many-to-many* communication (e.g., multicast), not just publish-subscribe.

The acronym **JEDI** stands for **J**oining **E**ncryption and **D**elegation for **I**oT.

License
-------
The code in this repository is open-source under the BSD 3-Clause License.
