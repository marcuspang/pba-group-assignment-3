use hex::ToHex;
use schnorrkel::Keypair;
// You can find the hashing algorithms in the exports from sp_core. In order to easily see what is
// available from sp_core, it might be helpful to look at the rust docs:
// https://paritytech.github.io/substrate/master/sp_core/index.html
use sp_core::*;

/// For simplicity in this exercise, we are only working with 128-bit hashes.
const HASH_SIZE: usize = 16;

/// Use the blake2 hashing algorithm to calculate the 128-bit hash of some input data
pub fn hash_with_blake(data: &[u8]) -> [u8; HASH_SIZE] {
    blake2_128(data)
}

/// Use the twox hashing algorithm to calculate the 128-bit hash of some input data
pub fn hash_with_twox(data: &[u8]) -> [u8; HASH_SIZE] {
    twox_128(data)
}

#[derive(Clone, PartialEq, Eq)]
pub enum HashAlgo {
    TwoX,
    Blake2,
}

/// Use the hashing algorithm variant specified in the argument to hash the data
pub fn hash_with(data: &[u8], algorithm: HashAlgo) -> [u8; HASH_SIZE] {
    match algorithm {
        HashAlgo::Blake2 => hash_with_blake(data),
        HashAlgo::TwoX => hash_with_twox(data),
    }
}

/// Return true iff data is the preimage of hash under the specified algorithm
pub fn is_hash_preimage(hash: [u8; HASH_SIZE], data: &[u8], algorithm: HashAlgo) -> bool {
    hash == hash_with(data, algorithm)
}

/// Add an integrity check to some data by using the blake2 hashing algorithm.
///
/// Hashes can also be used to check data integrity! We will implement a version of this using the
/// blake2 hashing algorithm. To append an integrity code to the end of some input, hash the data,
/// and append the 128-bit hash to the data. The result will look like `data | hash(data)`, using |
/// for concatenation.
pub fn add_integrity_check(data: &[u8]) -> Vec<u8> {
    let hash = hash_with_blake(data);
    let mut result = data.to_vec();
    result.extend_from_slice(&hash);
    return result;
}

/// Verify the integrity of some data via the checksum, and return the original data
///
/// In order to verify that the data is valid, we separate it out into the received hash and the
/// original data. Then, we hash the original data and compare it to the received hash. If it is
/// the same, we return the original data. Otherwise, we return an error.
///
/// Note that when receiving data that has an integrity check, it is important that we know
/// _exactly_ how the integrity check was generated. Most of the time, the integrity checks are
/// not able to be self-describing, so the verification end needs to know how to use the
/// integrity check.
pub fn verify_data_integrity(data: Vec<u8>) -> Result<Vec<u8>, ()> {
    if data.len() < 16 {
        return Err(());
    }
    let (encrypted_message, checksum) = data.split_at(data.len() - 16);
    if hash_with_blake(encrypted_message) != checksum {
        return Err(());
    }
    return Ok(encrypted_message.to_vec());
}

use rand::{rngs::SmallRng, seq::IteratorRandom, Rng, SeedableRng};
use std::{borrow::Borrow, cell::RefCell, collections::HashMap};
use strum::{EnumIter, IntoEnumIterator};
type HashValue = [u8; HASH_SIZE];

/// Now that we are comfortable using hashes, let's implement a classic commit-reveal scheme using a
/// public message board. This message board implements some functionality to allow people to communicate.
/// It allows people to commit to a message, and then later reveal that message. It also lets people
/// look up a commitment to see if the message has been revealed or not.
///
/// This message board will use the 128-bit Blake2 hashing algorithm.
#[derive(Debug)]
pub struct PublicMessageBoard {
    /// The commitals to this public message board. A 'None' value represents a commitment that has
    /// not been revealed. A 'Some' value will contain the revealed value corresponding to the
    /// commitment.
    commitals: HashMap<HashValue, Option<String>>,
    /// A seeded RNG used to generate randomness for committing
    ///
    /// STUDENTS: DO NOT USE THIS YOURSELF. The provided code already uses it everywhere necessary.
    rng: SmallRng,
}

impl PublicMessageBoard {
    /// Create a new message board
    pub fn new(rng_seed: u64) -> Self {
        PublicMessageBoard {
            commitals: HashMap::new(),
            rng: SmallRng::seed_from_u64(rng_seed),
        }
    }

    /// Post a commitment to the public message board, returning the message with added randomness
    /// and the commitment to share. If the commitment already exists, this does not modify the
    /// board, but returns the same values.
    ///
    /// The input messages should have some randomness appended to them so that an attacker cannot
    /// guess the messages to crack the hash. For compatibility with tests, do not use the message
    /// board's RNG other than the provided code below.
    ///
    /// Note that in reality, the commitment would be calculated offline, and only the commitment
    /// posted to the message board. However, in this example, we pretend that this is a "frontend"
    /// to the message board that handles that for you.
    pub fn post_commitment(&mut self, msg: String) -> (String, HashValue) {
        let randomness: [u8; 4] = self.rng.gen();
        let randomness_string = hex::encode(randomness);
        let msg_with_randomness = format!("{}{}", msg, randomness_string);

        let commitment = Self::reveal_to_commit(&msg_with_randomness);
        self.commitals.entry(commitment).or_insert(None);

        (msg_with_randomness, commitment)
    }

    /// Post a reveal for an existing commitment. The input should be the message with randomness added.
    ///
    /// Returns Ok(commitment) if the reveal was successful, or an error if the commitment wasn't
    /// found or has already been revealed.
    pub fn post_reveal(&mut self, committed_msg: String) -> Result<HashValue, ()> {
        let commitment: HashValue = hash_with_blake(committed_msg.as_bytes());

        match self.commitals.get(&commitment) {
            Some(current_commitment) => match current_commitment {
                Some(_) => Err(()), // commitment already revealed
                None => {
                    self.commitals.insert(commitment, Some(committed_msg));
                    Ok(commitment)
                }
            },
            None => Err(()), // commitment not found
        }
    }

    /// Check a certain commitment. Errors if the commitment doesn't exist, and otherwise returns
    /// None if the commitment has not been revealed, or the value if it has been revealed.
    pub fn check_commitment(&self, commitment: HashValue) -> Result<Option<String>, ()> {
        if let Some(value) = self.commitals.get(&commitment) {
            Ok(value.clone())
        } else {
            Err(())
        }
    }

    /// Helper method to convert from a reveal to the corresponding commitment.
    pub fn reveal_to_commit(reveal: &str) -> HashValue {
        hash_with_blake(reveal.as_bytes())
    }
}

/// Now, we will use our message board to play a game of rock paper scissors!
///
/// This enum tracks the game state. The game will always go in the following order:
///
/// 1. Player 1 commits to their play.
/// 2. Player 2 commits to their play.
/// 3. Player 1 reveals their play.
/// 4. Player 2 reveals their play. At this point, the game is over and either player 1 or player 2
///     has won!
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RPSGameState {
    NotStarted,
    PlayerCommitted {
        player_number: PlayerNumber,
        commitments: Vec<HashValue>,
    },
    AllCommitted {
        commitments: Vec<HashValue>,
    },
    PlayerRevealed {
        player_number: PlayerNumber,
        reveals: Vec<String>,
        commitments: Vec<HashValue>,
    },
    Completed {
        reveals: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RPSGame {
    state: RPSGameState,
    player_count: PlayerNumber,
}

impl RPSGame {
    // Return the winner if there is one, or none if it is a tie. Errors if the game state is not
    // terminal, or the committed strings are malformed.
    pub fn winner(&self) -> Result<(Option<PlayerNumber>, Option<RPSPlay>), ()> {
        match &self.state {
            RPSGameState::Completed { reveals } => Ok(reveals
                .iter()
                .map(|reveal| RPSPlay::from_string_with_randomness(reveal))
                .collect::<Result<Vec<RPSPlay>, _>>()?
                .iter()
                .enumerate()
                .fold((None, None), |acc, (index, &curr_play)| match acc {
                    (Some(player), Some(play)) => {
                        if curr_play.get_value() > play.get_value() {
                            (Some(PlayerNumber(index as u8)), Some(curr_play))
                        } else {
                            (Some(player), Some(curr_play))
                        }
                    }
                    (None, None) => (Some(PlayerNumber(index as u8)), Some(curr_play)),
                    (_, _) => (None, None),
                })),
            _ => Err(()),
        }
    }
}

/// The possible number of players
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayerNumber(u8); // TODO: allow for anyone to start the game?

impl PlayerNumber {
    pub fn get_next_player(&self) -> PlayerNumber {
        PlayerNumber(self.0 + 1)
    }

    pub fn is_first_player(&self) -> bool {
        self.0 == 0
    }
}

/// The possible plays in a game of rock paper scissors
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct RPSPlay {
    cards: [u8; 5],
}

impl std::fmt::Display for RPSPlay {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.cards
                .iter()
                .map(|card| card.to_string())
                .collect::<Vec<String>>()
                .join(",")
        )
    }
}

impl RPSPlay {
    /// Convert a string with 4 bytes of hex-encoded randomness at the end into an RPS play
    pub fn from_string_with_randomness(s: &str) -> Result<Self, ()> {
        let (value, randomness) = s.split_at(s.len() - 4 * 2);
        let value = value
            .split(",")
            .map(|s| s.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();
        Ok(Self {
            cards: value.try_into().map_err(|_| ())?,
        })
    }

    // TODO: update this according to Poker rules
    pub fn get_value(&self) -> u8 {
        self.cards.iter().sum()
    }

    pub fn draw_cards(nonce: HashValue) -> Self {
        let nonce = nonce[..8].try_into().unwrap();
        let nonce = u64::from_le_bytes(nonce);
        let mut rng = SmallRng::seed_from_u64(nonce);
        let mut cards = [0u8; 5];
        for card in cards.iter_mut() {
            *card = rng.gen_range(0..52) as u8;
        }
        Self { cards }
    }
}

/// A careful player of rock paper scissors, who only plays if the game state is correct.
pub struct RPSPlayer<'a> {
    /// The message board that this rock paper scissors player uses to communicate with the other
    /// player.
    ///
    /// This can be used mutably by using `self.message_board.borrow_mut()`.
    message_board: &'a RefCell<PublicMessageBoard>,
    /// Player index
    player_number: PlayerNumber,
    /// The string used to commit, with included randomness. This will always be the string
    /// representation of an RPSPlay
    previous_commitment_str: Option<String>,
    /// A seeded RNG used to generate randomness for deciding on a play.
    ///
    /// STUDENTS: DO NOT USE THIS YOURSELF. The provided code already uses it everywhere necessary.
    rng: SmallRng,

    keypair: Keypair,
    vrf: Option<HashValue>,
    play: Option<RPSPlay>,
}

impl<'a> RPSPlayer<'a> {
    /// Create a new player to use in a RPS game.
    pub fn new(
        rng_seed: u64,
        message_board: &'a RefCell<PublicMessageBoard>,
        player_order: PlayerNumber,
    ) -> Self {
        RPSPlayer {
            message_board,
            player_number: player_order,
            keypair: Keypair::generate(),
            previous_commitment_str: None,
            rng: SmallRng::seed_from_u64(rng_seed),
            play: None,
            vrf: None,
        }
    }

    pub fn draw_card(&mut self) {
        if self.vrf.is_none() {
            self.vrf = Some(hash_with_blake(self.keypair.public.to_bytes().as_ref()));
        }
    }

    pub fn reveal_card(&mut self) -> RPSPlay {
        let cards = RPSPlay::draw_cards(self.vrf.unwrap());
        self.play = Some(cards);
        cards
    }

    /// Make the next play as a careful player in a rock paper scissors game. You should only return
    /// the new game state if the old game state is consistent with the state of the message board
    /// and of the internal player state, otherwise error.
    ///
    /// In particular, make note of the following things:
    /// - If player 2 is committing, make sure that player 1 has already committed to
    ///     the message board. If not, error.
    /// - If player 1 is revealing, make sure that player 2 has already committed to
    ///     the message board. If not, error.
    /// - If player 2 is revealing, make sure that player 1 has already revealed to
    ///     the message board.
    /// - Once a player has seen the other player's commitment, make sure it is consistent
    ///     with any future game states. If it ever fails to be consistent, error.
    /// - DO NOT USE THE RANDOMNESS YOURSELF. This _will_ break automated tests.
    pub fn progress_game(&mut self, game_state: RPSGame) -> Result<RPSGame, ()> {
        // The student starter code is each match arm up to the `todo!()`.
        match game_state.state {
            RPSGameState::NotStarted if self.player_number == PlayerNumber(0) => {
                let play = self.play.ok_or(())?;
                let (msg_with_randomness, commitment) = self
                    .message_board
                    .borrow_mut()
                    .post_commitment(play.to_string());
                self.previous_commitment_str = Some(msg_with_randomness);
                Ok(RPSGame {
                    player_count: game_state.player_count,
                    state: RPSGameState::PlayerCommitted {
                        player_number: self.player_number,
                        commitments: vec![commitment],
                    },
                })
            }
            RPSGameState::PlayerCommitted {
                player_number,
                commitments,
            } =>
            // TODO: only the next player can progress game
            {
                if self.player_number == player_number.get_next_player() {
                    let play = self.play.ok_or(())?;
                    let prev_commitment = commitments.last().ok_or(())?;
                    self.message_board
                        .borrow()
                        .check_commitment(*prev_commitment)?;
                    let (msg_with_randomness, commitment) = self
                        .message_board
                        .borrow_mut()
                        .post_commitment(play.to_string());
                    self.previous_commitment_str = Some(msg_with_randomness);
                    let mut commitments = commitments.clone();
                    commitments.push(commitment);
                    if self.player_number.get_next_player() == game_state.player_count {
                        return Ok(RPSGame {
                            player_count: game_state.player_count,
                            state: RPSGameState::AllCommitted { commitments },
                        });
                    }
                    return Ok(RPSGame {
                        player_count: game_state.player_count,
                        state: RPSGameState::PlayerCommitted {
                            player_number: self.player_number,
                            commitments,
                        },
                    });
                }
                Err(())
            }
            RPSGameState::AllCommitted { commitments } if self.player_number.is_first_player() => {
                if let Some(p1_reveal) = self.previous_commitment_str.borrow() {
                    for commitment in commitments.clone() {
                        self.message_board.borrow().check_commitment(commitment)?;
                    }
                    let commitment_hash = self
                        .message_board
                        .borrow_mut()
                        .post_reveal(p1_reveal.clone())?;
                    let first_commitment = commitments.first().ok_or(())?;
                    if commitment_hash != *first_commitment {
                        return Err(());
                    }
                    return Ok(RPSGame {
                        player_count: game_state.player_count,
                        state: RPSGameState::PlayerRevealed {
                            player_number: self.player_number,
                            reveals: vec![p1_reveal.clone()],
                            commitments,
                        },
                    });
                }
                Err(())
            }
            RPSGameState::PlayerRevealed {
                reveals,
                commitments,
                player_number,
            } => {
                if self.player_number == player_number.get_next_player() {
                    // check if all reveals matches with commitment
                    for (index, current_reveal) in reveals.iter().enumerate() {
                        let commitment = commitments.get(index).ok_or(())?;
                        if !self
                            .message_board
                            .borrow()
                            .check_commitment(commitment.clone())?
                            .is_some_and(|reveal| reveal == *current_reveal)
                        {
                            return Err(());
                        }
                    }

                    let mut reveals = reveals;
                    if let Some(commitment) = self.previous_commitment_str.borrow() {
                        // TODO: only the next player can progress game
                        // method already checks if commitment exists
                        let commitment_hash = self
                            .message_board
                            .borrow_mut()
                            .post_reveal(commitment.to_string())?;
                        let actual_reveal = self
                            .message_board
                            .borrow()
                            .check_commitment(commitment_hash)?
                            .ok_or(())?;
                        reveals.push(actual_reveal);
                        if self.player_number.get_next_player() == game_state.player_count {
                            return Ok(RPSGame {
                                player_count: game_state.player_count,
                                state: RPSGameState::Completed { reveals },
                            });
                        }
                        return Ok(RPSGame {
                            player_count: game_state.player_count,
                            state: RPSGameState::PlayerRevealed {
                                player_number: self.player_number,
                                reveals,
                                commitments,
                            },
                        });
                    }
                }
                return Err(());
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_integrity_no_panics() {
        // This test might panic if they didn't check bounds before slicing
        let too_short_data = b"less than 16";
        assert!(verify_data_integrity(too_short_data.to_vec()).is_err())
    }

    #[test]
    fn hash_with_blake2_test() {
        let data = b"PBA Berkeley 2023!";
        let hash = hash_with_blake(data);
        let expected = hex::decode("47ab80e805a80033b7e0587ceb5c575d").unwrap();
        assert_eq!(&expected, &hash);
    }

    #[test]
    fn hash_with_twox_test() {
        let data = b"PBA Berkeley 2023!";
        let hash = hash_with_twox(data);
        let expected = hex::decode("c8a3248a3f671d43c01251a28494903c").unwrap();
        assert_eq!(&expected, &hash);
    }

    #[test]
    fn hash_with_test() {
        let data = b"PBA Berkeley 2023!";

        let twox_hash = hash_with(data, HashAlgo::TwoX);
        let expected_twox = hex::decode("c8a3248a3f671d43c01251a28494903c").unwrap();
        assert_eq!(&expected_twox, &twox_hash);

        let blake_hash = hash_with(data, HashAlgo::Blake2);
        let expected_blake = hex::decode("47ab80e805a80033b7e0587ceb5c575d").unwrap();
        assert_eq!(&expected_blake, &blake_hash);
    }

    #[test]
    fn hash_preimage_test() {
        let data = b"PBA Berkeley 2023!";
        // This data has been altered, misspelling "Berkeley"
        let bad_data = b"PBA Berkley 2023!";

        let mut twox_hash = [0u8; HASH_SIZE];
        hex::decode_to_slice("c8a3248a3f671d43c01251a28494903c", &mut twox_hash).unwrap();
        let mut blake_hash = [0u8; HASH_SIZE];
        hex::decode_to_slice("47ab80e805a80033b7e0587ceb5c575d", &mut blake_hash).unwrap();

        // works on actual data
        assert!(is_hash_preimage(twox_hash.clone(), data, HashAlgo::TwoX));
        assert!(is_hash_preimage(blake_hash.clone(), data, HashAlgo::Blake2));

        // Must be correct hashing algorithm
        assert!(!is_hash_preimage(blake_hash.clone(), data, HashAlgo::TwoX));

        // altered data doesn't verify, even though it's only 1 character off
        assert!(!is_hash_preimage(twox_hash, bad_data, HashAlgo::TwoX));
        assert!(!is_hash_preimage(blake_hash, bad_data, HashAlgo::Blake2));
    }

    #[test]
    fn add_integrity_check_test() {
        let data = b"PBA Berkeley 2023!";
        let blake = hex::decode("47ab80e805a80033b7e0587ceb5c575d").unwrap();
        let mut expected = Vec::new();
        expected.extend(data);
        expected.extend(blake);

        let integrity_checked_data = add_integrity_check(data);
        assert_eq!(data.len() + HASH_SIZE, integrity_checked_data.len());
        assert_eq!(expected, integrity_checked_data);
    }

    #[test]
    fn verify_integrity_test() {
        let data = b"PBA Berkeley 2023!";
        let blake = hex::decode("47ab80e805a80033b7e0587ceb5c575d").unwrap();
        let mut integrity_checked_data = Vec::new();
        integrity_checked_data.extend(data);
        integrity_checked_data.extend(blake);

        let mut bad_data = integrity_checked_data.clone();
        bad_data.remove(15);

        let integrity_checked_result = verify_data_integrity(integrity_checked_data).unwrap();
        assert_eq!(&data[..], &integrity_checked_result);
        assert!(verify_data_integrity(bad_data).is_err());
    }

    #[test]
    fn reveal_to_commit_test() {
        let input = "PBA Berkeley 2023!";
        let expected = hex::decode("47ab80e805a80033b7e0587ceb5c575d").unwrap();
        assert_eq!(&expected, &PublicMessageBoard::reveal_to_commit(input));
    }

    #[test]
    fn post_commitment_test() {
        let rng_seed = 2023;
        let mut pmb = PublicMessageBoard::new(rng_seed);

        let mut test_rng = SmallRng::seed_from_u64(rng_seed);
        let randomness: [u8; 4] = test_rng.gen();
        let randomness_string = hex::encode(randomness);

        let post = "PBA Berkeley 2023!".to_string();
        let (message, commit) = pmb.post_commitment(post.clone());
        assert_eq!(format!("{}{}", post.clone(), randomness_string), message);
        assert_eq!(blake2_128(message.as_bytes()), commit);
    }

    #[test]
    fn post_reveal_test() {
        let rng_seed = 2023;
        let mut pmb = PublicMessageBoard::new(rng_seed);

        let post = "PBA Berkeley 2023!".to_string();
        let (message, commit) = pmb.post_commitment(post.clone());
        let commit2 = pmb.post_reveal(message.clone());
        assert_eq!(Ok(commit), commit2);

        // this has not been committed first
        let bad_post = "PBA Cambridge 2022!".to_string();
        assert!(pmb.post_reveal(bad_post).is_err());
    }

    #[test]
    fn check_commitment_test() {
        let rng_seed = 2023;
        let mut pmb = PublicMessageBoard::new(rng_seed);

        let mut test_rng = SmallRng::seed_from_u64(rng_seed);
        let randomness: [u8; 4] = test_rng.gen();
        let randomness_string = hex::encode(randomness);

        let post = "PBA Berkeley 2023!".to_string();
        let (message, commit) = pmb.post_commitment(post.clone());

        assert_eq!(pmb.check_commitment(commit.clone()), Ok(None));
        assert_eq!(pmb.check_commitment([5u8; 16]), Err(()));

        pmb.post_reveal(message.clone()).unwrap();
        assert_eq!(pmb.check_commitment(commit), Ok(Some(message)));
    }

    // #[test]
    // fn rps_play_decode_strings() {
    //     let rock = "Rock00000000";
    //     let paper = "Paper00000000";
    //     let scissors = "Scissors00000000";
    //     assert_eq!(
    //         Ok(RPSPlay::Rock),
    //         RPSPlay::from_string_with_randomness(rock)
    //     );
    //     assert_eq!(
    //         Ok(RPSPlay::Paper),
    //         RPSPlay::from_string_with_randomness(paper)
    //     );
    //     assert_eq!(
    //         Ok(RPSPlay::Scissors),
    //         RPSPlay::from_string_with_randomness(scissors)
    //     );
    // }

    // #[test]
    // fn rps_play_decode_rejects_properly() {
    //     let not_at_start = "0Rock0Paper0";
    //     let wrong_randomness_length = "Paper000";
    //     assert!(RPSPlay::from_string_with_randomness(not_at_start).is_err());
    //     assert!(RPSPlay::from_string_with_randomness(wrong_randomness_length).is_err());

    //     let pmb = PublicMessageBoard::new(5);
    // }

    #[test]
    fn rps_progress_game_test_1() {
        let rng_seed = 2023;
        let pmb = PublicMessageBoard::new(rng_seed);
        let pmb_refcell = RefCell::new(pmb);

        // Because SmallRng is not necessarily deterministic across platforms, we need to replicate
        // the RNG calls in the RPS player and create an identically seeded message board in order
        // to know what play to expect in a test.
        let mut pmb2 = PublicMessageBoard::new(rng_seed);
        let mut p1_test_rng = SmallRng::seed_from_u64(rng_seed);
        let p1_expected_play = RPSPlay::draw_cards(p1_test_rng.gen());
        let (_, p1_commit) = pmb2.post_commitment(p1_expected_play.to_string());
        let expected = RPSGameState::PlayerCommitted {
            player_number: PlayerNumber(0),
            commitments: vec![p1_commit],
        };

        let mut p1 = RPSPlayer::new(rng_seed, &pmb_refcell, PlayerNumber(0));
        let state2 = p1
            .progress_game(RPSGame {
                state: RPSGameState::NotStarted,
                player_count: PlayerNumber(1),
            })
            .unwrap();
        assert_eq!(expected, state2.state);
    }

    #[test]
    fn rps_progress_player_test_2() {
        let rng_seed = 2023;
        let p2_rng_seed = 2024;
        let pmb = PublicMessageBoard::new(rng_seed);
        let pmb_refcell = RefCell::new(pmb);

        // Because SmallRng is not necessarily deterministic across platforms, we need to replicate
        // the RNG calls in the RPS player and create an identically seeded message board in order
        // to know what play to expect in a test.
        let mut pmb2 = PublicMessageBoard::new(rng_seed);
        let mut p1_test_rng = SmallRng::seed_from_u64(rng_seed);
        let mut p2_test_rng = SmallRng::seed_from_u64(p2_rng_seed);
        let p1_expected_play = RPSPlay::draw_cards(p1_test_rng.gen());
        let p2_expected_play = RPSPlay::draw_cards(p2_test_rng.gen());

        let (_, p1_commit) = pmb2.post_commitment(p1_expected_play.to_string());
        let (_, p2_commit) = pmb2.post_commitment(p2_expected_play.to_string());

        let expected = RPSGameState::AllCommitted {
            commitments: vec![p1_commit, p2_commit],
        };

        let mut p1 = RPSPlayer::new(rng_seed, &pmb_refcell, PlayerNumber(0));
        let mut p2 = RPSPlayer::new(p2_rng_seed, &pmb_refcell, PlayerNumber(1));
        let state2 = p1
            .progress_game(RPSGame {
                state: RPSGameState::NotStarted,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let state3 = p2
            .progress_game(RPSGame {
                state: state2,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        assert_eq!(expected, state3);
    }

    #[test]
    fn rps_progress_player_test_3() {
        let rng_seed = 2023;
        let p2_rng_seed = 2024;
        let pmb = PublicMessageBoard::new(rng_seed);
        let pmb_refcell = RefCell::new(pmb);

        // Because SmallRng is not necessarily deterministic across platforms, we need to replicate
        // the RNG calls in the RPS player and create an identically seeded message board in order
        // to know what play to expect in a test.
        let mut pmb2 = PublicMessageBoard::new(rng_seed);
        let mut p1_test_rng = SmallRng::seed_from_u64(rng_seed);
        let mut p2_test_rng = SmallRng::seed_from_u64(p2_rng_seed);
        let p1_expected_play = RPSPlay::draw_cards(p1_test_rng.gen());
        let p2_expected_play = RPSPlay::draw_cards(p2_test_rng.gen());

        let (p1_reveal, p1_commit) = pmb2.post_commitment(p1_expected_play.to_string());
        let (_, p2_commit) = pmb2.post_commitment(p2_expected_play.to_string());

        let expected = RPSGameState::PlayerRevealed {
            reveals: vec![p1_reveal],
            commitments: vec![p1_commit, p2_commit],
            player_number: PlayerNumber(0),
        };

        let mut p1 = RPSPlayer::new(rng_seed, &pmb_refcell, PlayerNumber(0));
        let mut p2 = RPSPlayer::new(p2_rng_seed, &pmb_refcell, PlayerNumber(1));
        let state2 = p1
            .progress_game(RPSGame {
                state: RPSGameState::NotStarted,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let state3 = p2
            .progress_game(RPSGame {
                state: state2,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let state4 = p1
            .progress_game(RPSGame {
                state: state3,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        assert_eq!(expected, state4);
    }

    #[test]
    fn rps_progress_player_full_game_test() {
        let rng_seed = 2023;
        let p2_rng_seed = 2024;
        let pmb = PublicMessageBoard::new(rng_seed);
        let pmb_refcell = RefCell::new(pmb);

        // Because SmallRng is not necessarily deterministic across platforms, we need to replicate
        // the RNG calls in the RPS player and create an identically seeded message board in order
        // to know what play to expect in a test.
        let mut pmb2 = PublicMessageBoard::new(rng_seed);
        let mut p1_test_rng = SmallRng::seed_from_u64(rng_seed);
        let mut p2_test_rng = SmallRng::seed_from_u64(p2_rng_seed);
        let p1_expected_play = RPSPlay::draw_cards(p1_test_rng.gen());
        let p2_expected_play = RPSPlay::draw_cards(p2_test_rng.gen());

        let (p1_reveal, _) = pmb2.post_commitment(p1_expected_play.to_string());
        let (p2_reveal, _) = pmb2.post_commitment(p2_expected_play.to_string());

        let expected = RPSGameState::Completed {
            reveals: vec![p1_reveal, p2_reveal],
        };

        let mut p1 = RPSPlayer::new(rng_seed, &pmb_refcell, PlayerNumber(0));
        let mut p2 = RPSPlayer::new(p2_rng_seed, &pmb_refcell, PlayerNumber(1));
        let state2 = p1
            .progress_game(RPSGame {
                state: RPSGameState::NotStarted,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let state3 = p2
            .progress_game(RPSGame {
                state: state2,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let state4 = p1
            .progress_game(RPSGame {
                state: state3,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let state5 = p2
            .progress_game(RPSGame {
                state: state4,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        assert_eq!(expected, state5);
    }

    #[test]
    fn rps_progress_initial_failures_test() {
        let rng_seed = 2023;
        let p2_rng_seed = 2024;
        let pmb = PublicMessageBoard::new(rng_seed);
        let pmb_refcell = RefCell::new(pmb);
        let mut p2 = RPSPlayer::new(p2_rng_seed, &pmb_refcell, PlayerNumber(1));

        // This test only covers some of the possible ways this could fail, so make sure to test on
        // your own!

        // p1's listed commit isn't on the message board!
        assert!(p2
            .progress_game(RPSGame {
                state: RPSGameState::PlayerCommitted {
                    player_number: PlayerNumber(1),
                    commitments: vec![[5u8; HASH_SIZE]]
                },
                player_count: PlayerNumber(2)
            })
            .is_err());
        // p1 has to start the game
        assert!(p2
            .progress_game(RPSGame {
                state: RPSGameState::NotStarted,
                player_count: PlayerNumber(2)
            })
            .is_err());
    }

    #[test]
    fn rps_progress_mismatch_failures_test() {
        let rng_seed = 2023;
        let p2_rng_seed = 2024;
        let pmb = PublicMessageBoard::new(rng_seed);
        let pmb_refcell = RefCell::new(pmb);
        let mut p1 = RPSPlayer::new(rng_seed, &pmb_refcell, PlayerNumber(0));
        let mut p2 = RPSPlayer::new(p2_rng_seed, &pmb_refcell, PlayerNumber(1));

        // This test only covers some of the possible ways this could fail, so make sure to test on
        // your own!

        let state2 = p1
            .progress_game(RPSGame {
                state: RPSGameState::NotStarted,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let state3 = p2
            .progress_game(RPSGame {
                state: state2,
                player_count: PlayerNumber(2),
            })
            .unwrap();
        let (p1_commit, p2_commit) = match state3.clone() {
            RPSGameState::AllCommitted { commitments } => (commitments[0], commitments[1]),
            _ => panic!("state3 should be both committed"),
        };

        // P1's previous commit doesn't match p1's current commit
        let bad_state3 = RPSGameState::AllCommitted {
            commitments: vec![[5u8; HASH_SIZE], p2_commit],
        };
        assert!(p1
            .progress_game(RPSGame {
                state: bad_state3,
                player_count: PlayerNumber(2)
            })
            .is_err());

        // P1's reveal doesn't match up with their previous commit
        let bad_state4 = RPSGameState::PlayerRevealed {
            reveals: vec!["Paper12121212".to_string()],
            commitments: vec![p1_commit, p2_commit],
            player_number: PlayerNumber(0),
        };
        assert!(p2
            .progress_game(RPSGame {
                state: bad_state4,
                player_count: PlayerNumber(2)
            })
            .is_err());
    }
}

fn main() {
    let mut rng_seed = SmallRng::seed_from_u64(123456789);
    let mut pmb = PublicMessageBoard::new(rng_seed.gen());
    let pmb_refcell = RefCell::new(pmb);
    let number_of_players = 10;
    let mut players = (0..number_of_players)
        .map(|player| RPSPlayer::new(rng_seed.gen(), &pmb_refcell, PlayerNumber(player)))
        .collect::<Vec<RPSPlayer>>();
    let mut game_state = RPSGame {
        state: RPSGameState::NotStarted,
        player_count: PlayerNumber(number_of_players),
    };

    for player_index in 0..(number_of_players as usize) {
        if let Some(player) = players.get_mut(player_index) {
            player.draw_card();
            let expected_play = player.reveal_card();
            // commit
            pmb_refcell
                .borrow_mut()
                .post_commitment(expected_play.to_string());
            game_state = player.progress_game(game_state).unwrap();
            println!("Player {} committed. State {:?}", player_index, game_state.state);
        }
    }

    for player_index in 0..(number_of_players as usize) {
        if let Some(player) = players.get_mut(player_index) {
            // reveal
            game_state = player.progress_game(game_state.clone()).unwrap();
            println!("Player {} committed. State {:?}", player_index, game_state.state);
        }
    }
    println!("Final State {:?}", game_state.state);

    let (winner, winning_play) = game_state.winner().unwrap();
    println!("Winner: {:?}, Play: {:?}", winner, winning_play);
}
