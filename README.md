# ZK Voting

ZK Voting Service is a REST API that provides a secure way to manage and conduct an online election. It uses the Actix framework and Rust's robust type system to ensure a secure and safe voting process.

## Features:

* Create a new election.
* Stop an existing election.
* Cast a vote in an ongoing election.
* Get the results of a completed election.
* All data sent to the server is signed with an ECDSA keypair, ensuring authenticity and integrity.

## Installation and Running:
To install the application, clone this repository and build it using `cargo`:

```shell
cargo build --release
```

The compiled binary will be in the `./target/release/` directory.

You can then run the server using the run command:

```shell
cargo run -- run -h 127.0.0.1 -p 8080
```

Replace 127.0.0.1 and 8080 with your preferred host and port.

## CLI Usage:
Once the server is running, it exposes several endpoints. Here's a brief overview:

`POST /new_election`: Creates a new election. Takes a SignedElectionData JSON object in the request body.
`POST /{id}/stop`: Stops an election. Takes a SignatureData JSON object in the request body.
`POST /{id}/vote`: Casts a vote in an election. Takes a VoteInput JSON object in the request body.
`GET /{id}/results`: Gets the results of a completed election. Returns a JSON array of results.
`POST /{id}/voter_id`: Get the voter ID for a particular signature. Takes a SignatureData JSON object in the request body.
For more details, see the [openapi.yaml](./openapi.yaml) document.

`run`: Runs the server. Takes -h for the host and -p for the port.
`sign`: Signs a message. Takes -m for the message string and -k for the secret key.
`keypair`: Generates a keypair. Takes optional -u for username and -p for password.

Example usage:

```shell
./zkballot run -h 127.0.0.1 -p 8080
./zkballot sign -m "hello" -k "secret_key"
./zkballot keypair -u "username" -p "password"
```