# Accountable Ring Signature based on DDH

a package of python code implementing the signature scheme proposed in the [Bootle 2015](https://eprint.iacr.org/2015/643) paper.

## Introduction

Accountable Ring Signature (ARS) is a signature scheme that:
- achieves k-anonymity through aggregation: signer is hidden in the members forming a ring of size k. Unpriviledged entities are unable to distinguish the signer from the other ring members with a probability higher than 1/k.
- achieves conditional anonymity: signer can be identified by an opener, based on the signature. The opener is designated at the time of signing by the signer.
- provides flexibilility: the ring is formed at the time of the signing, and formed by the signer. This allows the signer to control the ring size and the ring members, hence the anonymity level it has.
- is zero-knowledge: signature is produced with zero-knowledge proof. The interactive zkp in the original paper is transformed into non-interactive zkp for the purpose of producing signatures, using Fiat-Shamir transformation.

In this project, the 4 protocols given in the original paper are implemented with Python. Certain modifications are made on the original design to make the coding feasible. The modified design has been analysed and proved so that it achieves the same security properties as in the original design.

## Architecture
There are seven main functions in ARS scheme:

- system parameter initialisation: this function chooses system parameters, such as key length, prime ```p``` for the group of prime order, geneartor ```g``` of the group.
- key generation, ```keygen(sk,vk)```: this function generates a pair of public key and private key for any entities in the network.
- signing, ```ARSsign(sk, m)```: this function generates the signature on message ```m``` with the signer's private key ```sk```. It also forms the ring and chooses the opener. Its outputs are the ring ```R```, which is represented with the public keys of the ring members, the opener (represented by the opener's public key, ```dk```), and the signature ```sig```.
- verification, ```ARSverify(R,m,sig,dk)```: this function verifies the signature. It should verify that: the signature is generated on the message by one of the ring memebers; the signature can be opened by the opener. It outputs true or false.
- opening, ```ARSopen(ek, dk, sig)```: this function reveals the identity of the signer with the opener's private key ```ek```. It outputs the signer's public key ```vk``` and gives a NIZK proof of the opening results, ```P```, so that anyone can verify whether the given ```vk``` is actually the public key of the signer of this signature.
- opening verification, ```ARSopenverify(vk, sig, P)```: this function verifies the opening is correct, using the opened signer's public key ```vk```, the signature, and the proof ```P```. It outputs true or false.

To clarify, the notations of keys in this document are:
- ```sk, vk```: private key and public key of the signer. As the scheme is based on DDH, we have: ```vk = g^sk mod p```.
- ```ek, dk```: private key and pubic key of the opener. ```dk = g^ek mod p```.
- Ring R represented with a list of public keys: ```R = ${vk_0, vk_1, ..., vk_r}$``` for a ring of $r$ members.

## The Main Ideas
The main ideas of how to faciliate a signature scheme that achieves the properties as said in Intro are:
- To enable opening, signer should send its public key encrypted with the opener's public key. This is for the opener to be able to reveal the signer's public key. This encryption ```c``` will be included in the signature. ```c = Enc(ek, vk)```.
- To prove the signature contains the encryption ```c```, three relations need to be proved.
  - R1: there is an 1 and exactly one 1 in a list of numbers.
  - R2: there is an encryption of an 1 and exactly one 1 in a list of ciphertext.
  - R3: there is an encryption of the signer's public key in a list of ciphertext.
  
  Each of the three relations is proved based on the previous one.
- The opener can open the signer's public key easily by decrypting the encryption of ```vk``` in the signature. 
- To prove the opening is correct, the opener generates a zkp to prove R4: the ```vk``` it gives is indeed encrypted in ```c```.
