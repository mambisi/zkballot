use crate::ecdsa::{PublicKey, Signature};
use crate::gadget::gadget_set_membership::{
    gen_proof_of_set_membership, verify_proof_of_set_membership,
};
use crate::gadget::gadget_vsmt_2::VanillaSparseMerkleTree;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use digest::{Digest, FixedOutput};
use primitive_types::H256;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const ELECTION: &'static [u8] = b"Election";
#[derive(Clone)]
pub struct Election {
    voters: Vec<Scalar>,
    options: Vec<String>,
    ballot: Ballot,
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
    invalidate: HashSet<H256>,
    pub(crate) creator: PublicKey,
}

impl Election {
    pub fn new(voters: Vec<H256>, options: Vec<String>, creator: PublicKey) -> Self {
        let mut rng = rand::thread_rng();
        let voters: Vec<_> = voters
            .into_iter()
            .map(|item| item.to_fixed_bytes())
            .map(Scalar::from_bits)
            .collect();
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        Self {
            voters,
            options,
            ballot: Ballot {
                votes: Default::default(),
            },
            pc_gens,
            bp_gens,
            invalidate: Default::default(),
            creator,
        }
    }

    pub fn get_voter_id(&mut self, signature: Signature) -> anyhow::Result<VoterID> {
        let pubkey = signature.recover_public_key(b"voter")?;
        assert!(!self.invalidate.contains(&pubkey.hash()));
        let value = Scalar::from_bits(pubkey.hash().to_fixed_bytes());
        let voter_id = self.gen_proof_of_set_membership(value)?;
        self.invalidate.insert(pubkey.hash());
        return Ok(voter_id);
    }

    fn gen_proof_of_set_membership(&self, value: Scalar) -> anyhow::Result<VoterID> {
        let mut rng = rand::thread_rng();
        let randomness = Some(Scalar::random(&mut rng));
        let (proof, commitments) = gen_proof_of_set_membership(
            value,
            randomness,
            &self.voters,
            &mut rng,
            ELECTION,
            &self.pc_gens,
            &self.bp_gens,
        )?;
        Ok(VoterID { proof, commitments })
    }

    fn verify_proof_of_set_membership(&self, voter_id: VoterID) -> anyhow::Result<()> {
        let _ = verify_proof_of_set_membership(
            &self.voters,
            voter_id.proof,
            voter_id.commitments,
            ELECTION,
            &self.pc_gens,
            &self.bp_gens,
        )?;
        Ok(())
    }

    pub fn vote(&mut self, candidate: usize, voter_id: VoterID) -> anyhow::Result<()> {
        // Check if the the voter has voted
        // TODO need a better way to nullify proofs
        let voter_id_encoded =
            bincode::serde::encode_to_vec(&voter_id, bincode::config::standard())?;
        let voter_id_hash = H256::from(sha3(&voter_id_encoded));
        assert!(!self.invalidate.contains(&voter_id_hash));

        // Verify Vote
        assert!(self.verify_proof_of_set_membership(voter_id).is_ok());

        // Register Vote
        self.invalidate.insert(voter_id_hash);

        self.ballot.votes.insert(Vote {
            candidate,
            voter_id: voter_id_hash,
        });

        Ok(())
    }

    pub fn get_results(&self) -> HashMap<&String, usize> {
        let mut res = HashMap::new();

        for o in &self.options {
            res.insert(o, 0_usize);
        }

        for vote in &self.ballot.votes {
            let mut vote_count = res.get_mut(&self.options[vote.candidate]).unwrap();
            *vote_count += 1;
        }

        res
    }
}

#[derive(Clone)]
pub struct Ballot {
    votes: HashSet<Vote>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VoterID {
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
}

#[derive(Serialize, Deserialize, Debug, Hash, PartialOrd, PartialEq, Ord, Eq, Clone)]
pub struct Vote {
    candidate: usize,
    voter_id: H256,
}

pub fn sha3(input: &[u8]) -> H256 {
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(input);
    let out = hasher.finalize_fixed();
    H256::from_slice(&out[..])
}

#[cfg(test)]
mod test {
    use crate::ballot::{sha3, Election};
    use crate::ecdsa::Keypair;
    use primitive_types::{H256, U256};

    #[test]
    fn test_election() {
        let mut rng = rand::thread_rng();
        let alice = Keypair::generate(&mut rng);
        let bob = Keypair::generate(&mut rng);
        let kwaku = Keypair::generate(&mut rng);

        let mut election = Election::new(
            vec![
                alice.public.hash(),
                bob.public.hash(),
                H256::from([1; 32]),
                H256::from([2; 32]),
                H256::from([3; 32]),
                H256::from([4; 32]),
                H256::from([5; 32]),
            ],
            vec!["Elon".to_string(), "Bill".to_string(), "Bezos".to_string()],
            kwaku.public
        );

        let voter_id = election
            .get_voter_id(alice.secret.sign(b"voter").unwrap())
            .unwrap();

        election.vote(0, voter_id).unwrap();

        println!("{:?}", election.get_results());
    }
}
