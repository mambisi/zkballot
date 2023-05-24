use crate::ballot::{Election, VoterID};
use crate::ecdsa::Signature;
use actix_rt::System;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Serialize, Deserialize)]
struct VoteInput {
    candidate: usize,
    voter_id: VoterID,
}

#[derive(Serialize, Deserialize)]
struct ElectionData {
    voters: Vec<H256>,
    options: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct SignedElectionData {
    election_data: ElectionData,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct SignatureData {
    signature: String,
}
#[derive(Clone)]
pub struct Elections {
    elections: HashMap<H256, Election>,
}

type SafeElections = web::Data<Mutex<Elections>>;

async fn vote(
    data: web::Json<VoteInput>,
    elections: SafeElections,
    election_id: web::Path<H256>,
) -> impl Responder {
    let mut elections = elections.lock().unwrap();
    let election_id = election_id.into_inner();

    let election = elections.elections.get_mut(&election_id);

    if let Some(election) = election {
        match election.vote(data.candidate.clone(), data.voter_id.clone()) {
            Ok(_) => HttpResponse::Ok().finish(),
            Err(_) => HttpResponse::InternalServerError().finish(),
        }
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn get_voter_id(
    data: web::Json<SignatureData>,
    elections: SafeElections,
    election_id: web::Path<H256>,
) -> impl Responder {
    let mut elections = elections.lock().unwrap();
    let election_id = election_id.into_inner();

    let election = elections.elections.get_mut(&election_id);

    if let Some(election) = election {
        match election
            .get_voter_id(Signature::from_bytes(&hex::decode(&data.signature).unwrap()).unwrap())
        {
            Ok(voter_id) => HttpResponse::Ok().json(voter_id),
            Err(_) => HttpResponse::InternalServerError().finish(),
        }
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn results(elections: SafeElections, election_id: web::Path<H256>) -> impl Responder {
    let elections = elections.lock().unwrap();
    let election_id = election_id.into_inner();

    if let Some(election) = elections.elections.get(&election_id) {
        let results = election.get_results();
        HttpResponse::Ok().json(results)
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn new_election(
    data: web::Json<SignedElectionData>,
    elections: SafeElections,
) -> impl Responder {
    let mut elections = elections.lock().unwrap();

    let signature = Signature::from_bytes(&hex::decode(&data.signature).unwrap()).unwrap();

    let creator = signature
        .recover_public_key(
            serde_json::to_string(&data.election_data)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    creator
        .verify(
            serde_json::to_string(&data.election_data)
                .unwrap()
                .as_bytes(),
            &signature,
        )
        .unwrap();
    let voters = data.election_data.voters.clone();
    let options: Vec<String> = data.election_data.options.clone();

    let election = Election::new(voters, options, creator);

    let election_id = election.creator.hash();
    elections.elections.insert(election_id, election);

    HttpResponse::Ok().json(election_id)
}

async fn stop_election(
    data: web::Json<SignatureData>,
    elections: SafeElections,
    election_id: web::Path<H256>,
) -> impl Responder {
    let mut elections = elections.lock().unwrap();
    let election_id = election_id.into_inner();

    let election = elections.elections.get_mut(&election_id);

    let signature = Signature::from_bytes(&hex::decode(&data.signature).unwrap()).unwrap();

    if let Some(election) = election {
        let creator = signature.recover_public_key(election_id.as_bytes()).unwrap();
        creator.verify(election_id.as_bytes(), &signature).unwrap();

        if creator == election.creator {
            elections.elections.remove(&election_id);
            HttpResponse::Ok().finish()
        } else {
            HttpResponse::Forbidden().finish()
        }
    } else {
        HttpResponse::NotFound().finish()
    }
}

pub fn run_sever(host : IpAddr, port : u16)  -> std::io::Result<()>  {
    std::env::set_var("RUST_LOG", "actix_web=debug");
    env_logger::init();

    let elections = Elections {
        elections: HashMap::new(),
    };
    System::new().block_on(
        HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .app_data(Mutex::new(elections.clone()))
                .service(web::resource("/{id}/vote").route(web::post().to(vote)))
                .service(web::resource("/{id}/voter_id").route(web::post().to(vote)))
                .service(web::resource("/{id}/results").route(web::get().to(results)))
                .service(web::resource("/new_election").route(web::post().to(new_election)))
                .service(web::resource("/{id}/stop").route(web::post().to(stop_election)))
        })
            .bind((host, port))?
            .run()
    )
}
