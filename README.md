# Overview

This is a simplified Poker game, where the winner is decided from the largest sum of their card. Each card has a value in `[0, 51]`.

The game is simulated with arbitrary number of players, in a state machine fashion.

0. game runs like a state machine from the one in the assignment
1. each player starts by drawing cards (here, we initialize some VRF and store it with the user)
2. then, each player reveals their card
3. once every player has revealed their card, we evaluate all the revealed cards and determine the winner (currently the algorithm sums all the cards)

## Running the game

To run the game, run the following command

```bash
cargo run
```

To run the unit tests, run the following command

```bash
cargo test
```
