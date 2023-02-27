# Accountable Ring Signature based on DDH

a package of python code implementing the signature scheme proposed in the [Bootle 2015](https://eprint.iacr.org/2015/643) paper.

## Introduction

Accountable Ring Signature (ARS) is a signature scheme that:
- achieves k-anonymity through aggregation: signer is hidden in the members forming a ring of size k. Unpriviledged entities are unable to distinguish the signer from the other ring members with a probability higher than 1/k.
- achieves conditional anonymity: signer can be identified by an opener, based on the signature. The opener is designated at the time of signing by the signer.
- provides flexibilility: the ring is formed at the time of the signing, and formed by the signer. This allows the signer to control the ring size and the ring members, hence the anonymity level it has.
- is zero-knowledge: signature is produced with zero-knowledge proof. The interactive zkp in the original paper is transformed into non-interactive zkp for the purpose of producing signatures, using Fiat-Shamir transformation.

In this project, the 4 protocols given in the original paper are implemented with Python. Certain modifications are made on the original design to make the coding feasible. The modified design has been analysed and proved so that it achieves the same security properties as in the original design.
