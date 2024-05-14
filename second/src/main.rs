#![allow(unused_imports)]
#![allow(unused_variables)]
extern crate bellman;
extern crate bls12_381;
extern crate ff;
extern crate rand;
extern crate rand_core;
extern crate sha2;

use self::bellman::groth16::Parameters;

use self::rand::SeedableRng;

use self::rand::rngs::StdRng;

use self::bls12_381::Bls12;
use self::rand::{thread_rng, Rng};
use self::rand_core::RngCore;

use self::sha2::{Digest, Sha256};

use self::bellman::gadgets::sha256;
use self::bellman::groth16;
use self::rand_core::OsRng;
//use self::sha2::Sha256;
use self::bellman::gadgets::boolean::AllocatedBit;
use self::bellman::gadgets::boolean::Boolean;
use self::bellman::gadgets::multipack;
use self::bellman::gadgets::sha256::sha256;
use self::bellman::Circuit;
use self::bellman::ConstraintSystem;
use self::bellman::SynthesisError;
use self::ff::PrimeField;

use self::bellman::groth16::generate_random_parameters;

const REQUIRE_ZEROS: usize = 5;

/// Our own SHA-256d gadget. Input and output are in little-endian bit order.
fn sha256d<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    // Flip endianness of each input byte
    let input: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();

    let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
    let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

    // Flip endianness of each output byte
    Ok(res
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

struct MyCircuit {
    /// The input to SHA-256d we are proving that we know. Set to `None` when we
    /// are verifying a proof (and do not have the witness data).
    preimage: Option<[u8; 80]>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Compute the values for the bits of the preimage. If we are verifying a proof,
        // we still need to create the same constraints, so we return an equivalent-size
        // Vec of None (indicating that the value of each bit is unknown).
        println!("In circuit");
        let bit_values = if let Some(preimage) = self.preimage {
            preimage
                .into_iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 80 * 8]
        };

        assert_eq!(bit_values.len(), 80 * 8);

        println!("Citcuit witness");
        // Witness the bits of the preimage.
        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            // Allocate each bit.
            .map(|(i, b)| {
                let res = AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b);
                res
            })
            // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;
        println!("");
        // Compute hash = SHA-256d(preimage).
        let hash = sha256d(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;

        //for (i, bits) in hash.chunks(Scalar::CAPACITY as usize).enumerate() {}
        println!("Circuit end");
        for i in 0..hash.len() {
            let bit = &hash[i];
            //print!("{}", bit)
            if bit.get_value().is_some() {
                if i < REQUIRE_ZEROS && bit.get_value().unwrap() {
                    panic!("Requires leading zeros!");
                }
                if bit.get_value().unwrap() {
                    print!("1");
                } else {
                    print!("0");
                }
            } else {
                print!("2");
            }
        }
        println!("");

        // Expose the vector of 32 boolean variables as compact public inputs.
        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

fn main() {
    // Create parameters for our circuit. In a production deployment these would
    // be generated securely using a multiparty computation.

    let mut rng = StdRng::from_rng(thread_rng()).unwrap();

    let params: Parameters<Bls12> = {
        let c = MyCircuit { preimage: None };

        generate_random_parameters(c, &mut rng).unwrap()
    };

    // Prepare the verification key (for proof verification).
    let pvk = groth16::prepare_verifying_key(&params.vk);
    // 7677777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777

    let preimage_str =
        "76777777777777777777777777777777777777777777777777777777777777777777777777777777";

    let mut preimage: [u8; 80] = [0; 80]; // Initialize an array of 80 bytes with all elements set to 0

    // Convert each character in the string to its corresponding byte value
    for (i, byte_char) in preimage_str.bytes().enumerate() {
        preimage[i] = byte_char;
    }

    let hash = Sha256::digest(&Sha256::digest(&preimage));
    let bits: Vec<bool> = hash
        .into_iter()
        .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
        .flatten()
        .map(|b| b)
        .collect();
    /*   let mut bits = String::new();
    for &byte in &preimage {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            bits.push_str(&format!("{}", bit));
        }
    } */
    print!("START ");
    for bit in &bits {
        if *bit {
            print!("1");
        } else {
            print!("0");
        }
    }
    println!();

    // Create an instance of our circuit (with the preimage as a witness).
    let c = MyCircuit {
        preimage: Some(preimage),
    };

    // Create a Groth16 proof with our parameters.
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

    // Pack the hash as inputs for proof verification.
    let hash_bits = multipack::bytes_to_bits_le(&hash);
    let inputs = multipack::compute_multipacking(&hash_bits);

    // Check the proof!
    assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
    println!("Proof verified!");
}
