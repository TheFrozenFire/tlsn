#### Motivation:

The following discrepancy demonstrates how the User can use 2 different plaintexts in the 2 gc execution phases.

In light of this, we should carefully word how we present the purpose of phase 2. The purpose is not for the User to prove that she used the same plaintext in both gc executions. But rather the purpose is to convince the Notary that regardless of what plaintext the User used, she could not have leaked the Notary's secret. 

#### The "attack":

Suppose the User wants to cheat. She prepares the following:

For phase 1 when Notary is the evaluator:
- she honestly sends her plaintext input $P$.
- instead of honestly sending the decoding info $D$ (the LSBs) to the Notary, she sends $D'$ with the last bit flipped.

For phase 2 when User is the evaluator:
- she requests via OT the inputs for malicious plaintext $P'$ == $P$ with the last bit flipped.  



The result will be:

For phase 1: the Notary derives $c$ in Step 3 with the last bit flipped.

For phase 2: The Notary derives $c$ in Step 9 with the last bit flipped.


This is not an attack on the protocol per-se since the User is bound to send the wrong $c$ to the server.
