/// ethrun.rs -- directly run EVM bytecode

// Copyright 2016  Nexus Development, LLC

// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see https://www.gnu.org/licenses.

/// Commentary:

// This program is intended to be used as a low-level building block
// for higher-level applications (such as running EVM-based tests).

extern crate ethcore;
extern crate ethcore_devtools;
extern crate ethcore_io;
extern crate ethcore_util;
extern crate ethkey;
extern crate rustc_serialize;
extern crate serde_json as json;

use ethcore::client::BlockChainClient;
use ethcore::client::MiningBlockChainClient;
use ethcore_util::FromHex;
use ethcore_util::U256;
use rustc_serialize::hex::ToHex;
use std::io::Read;
use std::sync::Arc;

fn main() {
  // Parity comes with a default consensus-free mining setup
  let mut genesis = ethcore::spec::Spec::new_instant();

  // The secret of the default account is the empty brainwallet
  let account = ethkey::KeyPair::from_secret(ethkey::Secret::from(
    "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"
  )).unwrap();

  // We need a large gas limit so we can run large contracts
  genesis.gas_limit = U256::from("ffffffffffffffffffff");

  // Create a standard temporary blockchain client
  let client = ethcore::client::Client::new(
    ethcore::client::ClientConfig::default(), &genesis,
    &ethcore_devtools::RandomTempPath::new().as_path(),
    Arc::new(ethcore::miner::Miner::with_spec(&genesis)),
    ethcore_io::IoChannel::disconnected(),
    &ethcore_util::DatabaseConfig::with_columns(ethcore::db::NUM_COLUMNS),
  ).unwrap();

  // For now, all our transactions go in a single block
  let mut block = client.prepare_open_block(
    account.address(), (0.into(), 1.into()), vec![]
  );

  // The bytecode to be deployed comes from standard input
  let mut input = String::new();
  std::io::stdin().read_to_string(&mut input).unwrap();

  // Deploy the bytecode to the address of the first nonce
  let nonce = client.latest_nonce(&account.address());
  let contract = ethcore::contract_address(&account.address(), &nonce);
  block.push_transaction(ethcore::transaction::Transaction {
    action    : ethcore::transaction::Action::Create,
    data      : input.from_hex().unwrap(),
    value     : U256::from("ffffffffffffffffffffffff"),
    gas       : U256::from("ffffffffffff"),
    gas_price : U256::from(0),
    nonce     : nonce,
  }.sign(&account.secret(), None), None).unwrap();

  // Push one additional transaction for each command line argument
  for (i, calldata) in std::env::args().skip(1).enumerate() {
    block.push_transaction(ethcore::transaction::Transaction {
      action    : ethcore::transaction::Action::Call(contract),
      data      : calldata.from_hex().unwrap(),
      value     : U256::from(0),
      gas       : U256::from("ffffffffffff"),
      gas_price : U256::from(0),
      nonce     : nonce + U256::from(1 + i),
    }.sign(&account.secret(), None), None).unwrap();
  }

  // Seal the block in order to be able to replay the transactions
  client.import_sealed_block(
    block.close_and_lock().seal(&*genesis.engine, vec![]).unwrap()
  ).unwrap();

  // Replaying the transactions lets us extract results from them
  println!("{}", json::Value::Array((0 .. std::env::args().len()).map(|i| {
    match client.replay(
      ethcore::client::TransactionID::Location(
        ethcore::client::BlockID::Pending, i
      ),
      ethcore::client::CallAnalytics {
        transaction_tracing : true,  // Needed to detect crashes
        vm_tracing          : false,
        state_diffing       : false,
      },
    ).unwrap() {
      ethcore::client::Executed { trace, logs, output, .. } => {
        let mut fields = json::Map::new();

        fields.insert(
          "success".to_string(),
          json::Value::Bool(match trace[0].result {
            ethcore::trace::trace::Res::FailedCall(_) => false,
            _ => true,
          }),
        );

        fields.insert(
          "logs".to_string(),
          json::Value::Array(logs.iter().map(|log| {
            let mut fields = json::Map::new();

            fields.insert(
              "address".to_string(),
              json::Value::String(log.address.to_vec().to_hex()),
            );

            fields.insert(
              "topics".to_string(),
              json::Value::Array(log.topics.iter().map(|topic| {
                json::Value::String(topic.to_vec().to_hex())
              }).collect())
            );

            fields.insert(
              "data".to_string(),
              json::Value::String(log.data.to_hex()),
            );

            json::Value::Object(fields)
          }).collect())
        );

        fields.insert(
          "output".to_string(),
          json::Value::String(output.to_hex()),
        );

        json::Value::Object(fields)
      }
    }
  }).collect()))
}
