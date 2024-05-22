# High-level Approach

1. generate `N` keypairs, 1 for each user
2. request user to pick a card + random input to generate VRF
3. user commits (card, random input)
4. keep track of chosen cards and derive winner
   - sum of all card values
5. reveal all commitments + log all card & respective VRF & public key for other users to validate
