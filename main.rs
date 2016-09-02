// Copyright 2016 Nexus Development

// Quickrun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Quickrun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Quickrun.  If not, see <http://www.gnu.org/licenses/>.

//! Quick contract runner for testing.

#[macro_use] extern crate lazy_static;

extern crate docopt;

extern crate serde_json as json;
extern crate rustc_serialize;
extern crate regex;

extern crate ethcore;
extern crate ethcore_util as util;
extern crate ethcore_devtools as devtools;
extern crate ethcore_io as io;
extern crate ethcore_logger as logger;

extern crate ethstore;
extern crate ethabi as abi;

use regex::Regex;

use devtools::RandomTempPath;

use ethcore::transaction::{Transaction, SignedTransaction, Action};
use ethcore::account_provider::AccountProvider;
use ethcore::client::{Client, ClientConfig};
use ethcore::client::{BlockID, MiningBlockChainClient, BlockChainClient};
use ethcore::client::Executed;
use ethcore::engines::Engine;
use ethcore::spec::Spec;
use ethcore::miner::Miner;

use ethstore::ethkey::Secret;

use io::IoChannel;

use util::{U256, FromHex, Uint};

use std::str::FromStr;
use std::sync::Arc;

const USAGE: &'static str = r#"
Quick Ethereum unit test runner based on the Ethcore platform.

Expects output from `solc --combined-json=abi,bin` on stdin.

Test suite should be compatible with Dapple's test framework.

Usage:
  quickrun --test-contract=<contract>

Options:
  -h --help           Show this screen
"#;

#[derive(Debug, RustcDecodable)]
struct Args {
  pub flag_test_contract: String
}

// A bug in Solidity gives stuff like { "type": "MyContract"} for event fields.
// We must transform them to "address" ourselves until this is fixed in solc.
//
// https://github.com/ethereum/solidity/issues/489
// https://github.com/ethcore/ethabi/issues/7
//
fn fixup_contract_types(value: json::Value) -> json::Value {
  lazy_static! {
    static ref CONTRACT_TYPE_PATTERN: Regex = Regex::new("^[A-Z]").unwrap();
  }

  match value {
    json::Value::Array(xs) =>
      json::Value::Array(
        xs.iter().map(|x| fixup_contract_types(x.clone())).collect()
      ),
    json::Value::Object(o) =>
      json::Value::Object(
        o.into_iter().map(|(k, v)|
          match (k, v) {
            (ref k, json::Value::String(ref v))
              if k == "type" && CONTRACT_TYPE_PATTERN.is_match(&v) =>
                (k.clone(), json::Value::String("address".to_string())),
            (ref k, ref v) => (k.clone(), fixup_contract_types(v.clone()))
          }
        ).collect()
      ),
    _ => value
  }
}

struct Runner<'a> {
  client: &'a Client,
  engine: &'a Engine,
  account: util::H160,
  secret: util::H256
}

impl<'a> Runner<'a> {
  fn execute(&self, transaction: Transaction) {
    let mut block = self.client.prepare_open_block(
      self.account,
      (1.into(), 1_000_000.into()), // XXX what is this actually?
      vec![]
    );
  
    block.push_transaction(
      transaction.sign(&self.secret), None
    ).unwrap();
  
    self.client.import_sealed_block(
      block.close_and_lock().seal(&*self.engine, vec![]).unwrap()
    ).unwrap();
    
    self.client.flush_queue();
  }

  fn create(&self, code: &Vec<u8>) -> util::H160 {
    let contract_address = self.next_contract_address();

    self.execute(Transaction {
      action: Action::Create,
      value: U256::from(0),
      data: code.clone(),
      gas: U256::from(50_000_000), // XXX parameterize gas
      gas_price: U256::one(),
      nonce: self.client.latest_nonce(&self.account)
    });

    contract_address
  }

  fn execute_call(&self, contract: util::H160, spec: &abi::spec::Function) {
    self.execute(Transaction {
      nonce: self.client.latest_nonce(&self.account),
      action: Action::Call(contract),
      gas: U256::from(50_000_000), // XXX parameterize gass
      gas_price: U256::default(),
      value: U256::default(),
      data: abi::Function::new(spec.clone()).encode_call(vec![]).unwrap()
    });
  }

  fn transient_call(&self, contract: util::H160, spec: &abi::spec::Function)
    -> Result<ethcore::client::Executed, ethcore::error::CallError>
  {
    self.client.call(&self.fake_sign(Transaction {
      nonce: self.latest_nonce(util::Address::default()),
      action: Action::Call(contract),
      gas: U256::from(50_000_000),
      gas_price: U256::default(),
      value: U256::default(),
      data: abi::Function::new(spec.clone()).encode_call(vec![]).unwrap()
    }), BlockID::Latest, Default::default())
  }

  fn next_contract_address(&self) -> util::H160 {
    ethcore::contract_address(
      &self.account, &self.client.latest_nonce(&self.account)
    )
  }

  fn latest_nonce(&self, address: util::H160) -> util::U256 {
    self.client.latest_nonce(&address)
  }

  fn fake_sign(&self, transaction: Transaction) -> SignedTransaction {
    transaction.fake_sign(self.account)
  }
}

fn main() {
  match run() {
    Ok(_) => {},
    Err(e) => {
      println!("error: {}", e);
      std::process::exit(1)
    }
  }
}

fn run() -> Result<(), String> {
  let log_config = logger::Config {
    mode: None,
    color: true,
    file: None
  };
  
  logger::setup_log(&log_config).unwrap();

  let args: Args = docopt::Docopt::new(USAGE).and_then(|d| d.decode())
    .unwrap_or_else(|e| e.exit());

  let x: json::Value = try!(
    json::from_reader(std::io::stdin()).or(Err("invalid JSON on stdin"))
  );

  let root: &json::Value = try!(
    try!(x.find("contracts").ok_or(
      "no `contracts` field; is stdin data from solc --combined-json?"
    )).find(&args.flag_test_contract).ok_or(
      format!("contract {} not found", args.flag_test_contract)
    )
  );
  
  let bin_hex = try!(
    try!(
      root.find("bin").ok_or("no `bin` field in contract JSON")
    ).as_string().ok_or("`bin` field was not a string")
  );
  
  let code = try!(
    bin_hex.to_string().from_hex().or(Err("`code` field was not valid hex"))
  );
  
  let abi_json = try!(
    try!(
      root.find("abi").ok_or("no `abi` field in contract JSON")
    ).as_string().ok_or("`abi` field was not a string")
  );
  
  let abi_value: json::Value = try!(
    json::from_str(abi_json).map_err(|e|
      format!("error decoding `abi` field as JSON: {}", e)
    )
  );
  
  let abi_fixed = fixup_contract_types(abi_value.clone());

  let abi_fixed_json = json::to_string(&abi_fixed).unwrap();
  let abi: abi::Interface = try!(
    abi::Interface::load(abi_fixed_json.as_bytes()).map_err(|e|
      format!("error parsing ABI: {:?}", e)
    )
  );

  let abi_failed = try!(
    abi.function("failed".to_string()).ok_or(
      "ABI has no `failed` method; is it a Dapple test?"
    )
  );
  
  let abi_setup = abi.function("setUp".to_string());

  lazy_static! {
    static ref TEST_PATTERN: Regex = Regex::new("^test").unwrap();
  }

  // Assumes the ABI JSON is correct since ethabi was able to parse it.
  let abi_tests: Vec<abi::spec::Function> =
    abi_value.as_array().unwrap().iter().filter_map(|x|
      match *(x.find("type").unwrap()) {
        json::Value::String(ref t) if t == "function" =>
          match x.find("name") {
            Some(name) if TEST_PATTERN.is_match(name.as_string().unwrap()) =>
              Some(
                abi.function(
                  name.as_string().unwrap().to_string()
                ).unwrap()
              ),
            _ => None
          },
        _ => None
      }
    ).collect();

  // let abi_events: Vec<(&str, abi::Event)> =
  //   abi_value.as_array().unwrap().iter().filter_map(|x|
  //     match *(x.find("type").unwrap()) {
  //       json::Value::String(ref t) if t == "event" => {
  //         let name = x.find("name").unwrap().as_string().unwrap();
  //         Some((
  //           name,
  //           abi::Event::new(
  //             abi.event(
  //               name.to_string()
  //             ).unwrap()
  //           )
  //         ))
  //       },
  //       _ => None
  //     }
  //   ).collect();

  let temp = RandomTempPath::new();
  let path = temp.as_path();
  let spec = Spec::load(include_bytes!("./chain.json"));

  let miner = Arc::new(Miner::with_spec(&spec));
  let client = Client::new(
    ClientConfig::default(),
    &spec,
    &path,
    miner,
    IoChannel::disconnected()
  ).unwrap();

  let secret = Secret::from_str(
    "a100df7a048e50ed308ea696dc600215098141cb391e9527329df289f9383f65"
  ).unwrap();

  let account_provider = AccountProvider::transient_provider();
  let account = account_provider.insert_account(secret.clone(), "").unwrap();
  account_provider.unlock_account_permanently(account, "".to_string()).unwrap();

  let runner = Runner {
    client: &client,
    engine: &*spec.engine,
    account: account,
    secret: secret
  };

  for func in abi_tests {
    let x = run_test(&runner, &code, &abi_setup, &abi_failed, &func);
    match x {
      Ok((failed, Executed { logs, .. })) => {
        println!(
          "{} {} ({} logs)",
          if failed { "FAIL" } else {"OK  "},
          func.name,
          logs.len()
        );

        // // There seems to be something wrong with how ethabi decodes events,
        // // like it doesn't consider the event name or something?
        // for log in logs {
        //   let topics: Vec<[u8; 32]> = log.topics.iter().map(|h| h.0).collect();
        //   match abi_events.iter().filter_map(|&(name, ref e)|
        //     e.decode_log(topics.clone(), log.data.clone()).ok().map(|d| (name, d))
        //   ).next() {
        //     Some(decoded) => println!("{:?}", decoded),
        //     _ => println!("unknown event")
        //   }
        // }
      },
      Err(e) =>
        println!("FAIL {:?}", e),
    }
  }

  Ok(())
}

fn run_test(
  runner: &Runner,
  code: &Vec<u8>,
  abi_setup: &Option<abi::spec::Function>,
  abi_failed: &abi::spec::Function,
  spec: &abi::spec::Function
) -> Result<(bool, ethcore::client::Executed), ethcore::error::CallError>
{
  let contract = runner.create(code);
  
  abi_setup.clone().map(|setup| runner.execute_call(contract, &setup));

  runner.transient_call(contract, spec).map(|result| {
    runner.execute_call(contract, spec);
    let failed = runner.transient_call(contract, abi_failed).unwrap().output;
    (failed.last() == Some(&1), result)
  })
}
