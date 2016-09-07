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
extern crate ethjson;

extern crate tiny_keccak as keccak;

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
  quickrun --test-contract=<contract> [options]
  quickrun --list-contracts

Options:
  --logs              Print log entries
  --trace             Print "externals" trace
  --vmtrace           Print VM trace
  --diff              Print state diffs
  --json              Use JSON output format
  -h --help           Show this screen
"#;

#[derive(Debug, RustcDecodable)]
struct Args {
  pub flag_list_contracts: bool,
  pub flag_test_contract: String,
  pub flag_logs: bool,
  pub flag_trace: bool,
  pub flag_vmtrace: bool,
  pub flag_diff: bool,
  pub flag_json: bool,
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
    let analytics = ethcore::client::CallAnalytics {
      transaction_tracing: true,
      vm_tracing: true,
      state_diffing: true,
    };
    self.client.call(&self.fake_sign(Transaction {
      nonce: self.latest_nonce(util::Address::default()),
      action: Action::Call(contract),
      gas: U256::from(50_000_000),
      gas_price: U256::default(),
      value: U256::default(),
      data: abi::Function::new(spec.clone()).encode_call(vec![]).unwrap()
    }), BlockID::Latest, analytics)
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

  let contracts: &json::Value = try!(x.find("contracts").ok_or(
      "no `contracts` field; is stdin data from solc --combined-json?"
  ));
  
  if args.flag_list_contracts {
    for c in contracts.as_object().unwrap().keys() {
      println!("{}", c);
    }
    return Ok(());
  }

  let root: &json::Value = try!(
    contracts.find(&args.flag_test_contract).ok_or(
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

  let abi_events: Vec<(&str, Vec<u8>, abi::Event)> =
    abi_value.as_array().unwrap().iter().filter_map(|x|
      match *(x.find("type").unwrap()) {
        json::Value::String(ref t) if t == "event" => {
          let name = x.find("name").unwrap().as_string().unwrap();

          let inputs = x.find("inputs").unwrap().as_array().unwrap().iter()
            .map(|x| x.find("type").unwrap().as_string().unwrap().to_string())
            .collect::<Vec<String>>()
            .join(",");

          // XXX: clarify what's going on, refactor
          // SHA3("MyEvent(uint,address)")
          let mut sponge = keccak::Keccak::new_keccak256();
          let mut hash = [0u8; 4];
          sponge.update(
            format!("{}({})", name, inputs).as_bytes()
          );
          sponge.finalize(&mut hash);
          
          Some((
            name,
            hash.to_vec(),
            abi::Event::new(
              abi.event(
                name.to_string()
              ).unwrap()
            )
          ))
        },
        _ => None
      }
    ).collect();

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

  let mut json_array = vec![];

  for func in abi_tests {
    let x = run_test(&runner, &code, &abi_setup, &abi_failed, &func);
    match x {
      Ok((failed, Executed { logs, trace, vm_trace, state_diff, .. })) => {
        let mut json_keys = std::collections::BTreeMap::new();

        if args.flag_json {
          json_keys.insert("name".to_string(), json::Value::String(func.name));
          json_keys.insert("ok".to_string(), json::Value::Bool(!failed));
          if args.flag_trace {
            json_keys.insert("trace".to_string(),
              json::Value::String(format!("{:?}", trace)));
          }
          if args.flag_vmtrace {
            json_keys.insert("vmtrace".to_string(),
              json::Value::String(format!("{:?}", vm_trace)));
          }
          if args.flag_diff {
            json_keys.insert("diff".to_string(),
              json::Value::String(format!("{:?}", state_diff)));
          }
        } else {
          println!(
            "{} {} ({} logs)",
            if failed { "FAIL" } else {"OK  "},
            func.name,
            logs.len()
          );
  
          if args.flag_trace {
            println!("TRACE {:?}\n", trace);
          }
          if args.flag_vmtrace {
            println!("VMTRACE {:?}\n", vm_trace);
          }
          if args.flag_diff {
            println!("STATEDIFF {:?}\n", state_diff);
          }
        }
        
        if args.flag_logs  {
          let decoded_logs = logs.iter().map(|log| {
            let topics: Vec<[u8; 32]> = log.topics.iter().map(|h| h.0).collect();
            let interface_topic = log.topics.get(0).unwrap().0[0..4].to_vec();
            abi_events.iter().filter_map(|&(name, ref hash, ref e)| {
              if *hash == interface_topic {
                e.decode_log(
                  topics.clone(), log.data.clone()
                ).ok().map(|d| (name, d.params))
              } else {
                None
              }
            }).next()
          });

          if args.flag_json {
            json_keys.insert(
              "logs".to_string(),
              json::Value::Array(decoded_logs.map(|x|
                match x {
                  Some((name, d)) => {
                    let mut log_keys = std::collections::BTreeMap::new();
                    log_keys.insert(
                      "name".to_string(), json::Value::String(name.to_string())
                    );
                    log_keys.insert(
                      "params".to_string(),
                      params_to_json(&d)
                    );
                    json::Value::Object(log_keys)
                  },
                  None => {
                    let mut log_keys = std::collections::BTreeMap::new();
                    log_keys.insert("name".to_string(), json::Value::Null);
                    json::Value::Object(log_keys)
                  }
                }
              ).collect())
            );
          } else {
            for decoded_log in decoded_logs {
              match decoded_log {
                Some((name, d)) => println!("{} {:?}", name, d),
                None => ()
              }
            }
            println!("");
          }
        }

        if args.flag_json {
          json_array.push(json::Value::Object(json_keys));
        }
      },
      Err(e) =>
        println!("FAIL {:?}", e),
    }
  }

  if args.flag_json {
    println!("{}", json::Value::Array(json_array));
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

fn params_to_json(
  params: &Vec<(String, abi::spec::ParamType, abi::Token)>
) -> json::Value {
  let mut array = vec![];
  for (name, paramtype, token) in params.clone() {
    let mut keys = std::collections::BTreeMap::new();
    keys.insert("name".to_string(), json::Value::String(name));
    keys.insert("type".to_string(), json::Value::String(format!("{}", paramtype)));
    keys.insert("value".to_string(), json::Value::String(format!("{}", token)));
    array.push(json::Value::Object(keys));
  }
  json::Value::Array(array)
}