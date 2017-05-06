/// ethrun.rs -- directly run EVM bytecode (using Parity)

// Copyright (C) 2016, 2017  Mikael Brockman <mikael@dapphub.com>
// Copyright (C) 2016, 2017  Daniel Brockman <daniel@dapphub.com>

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
use std::io::BufRead;
use std::sync::Arc;

fn main() {
  let mut genesis = ethcore::spec::Spec::new_instant();

  let account = ethkey::KeyPair::from_secret(ethkey::Secret::from(
    "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"
  )).unwrap();

  genesis.gas_limit = U256::from("ffffffffffffffffffff");

  let client = ethcore::client::Client::new(
    ethcore::client::ClientConfig::default(),
    &genesis,
    &ethcore_devtools::RandomTempPath::new().as_path(),
    Arc::new(ethcore::miner::Miner::with_spec(&genesis)),
    ethcore_io::IoChannel::disconnected(),
    &ethcore_util::DatabaseConfig::with_columns(ethcore::db::NUM_COLUMNS),
  ).unwrap();

  let block_author = account.address();
  let gas_range_target = (0.into(), 1.into());
  let extra_data = vec![];
  let mut block = client.prepare_open_block(
    block_author, gas_range_target, extra_data
  );

  let nonce = client.latest_nonce(&account.address());
  let input = std::io::stdin();
  let lines: Vec<String> = input.lock().lines().map(|result| {
    result.unwrap()
  }).collect();

  for (i, line) in lines.iter().enumerate() {
    block.push_transaction(ethcore::transaction::Transaction {
      action    : ethcore::transaction::Action::Create,
      data      : line.from_hex().unwrap(),
      value     : U256::from("ffffffffffffffffffffffff"),
      gas       : U256::from("ffffffffffff"),
      gas_price : U256::from(0),
      nonce     : nonce + U256::from(i),
    }.sign(&account.secret(), None), None).unwrap();
  }

  let create_nonce = nonce + U256::from(lines.len() - 1);
  let address = ethcore::contract_address(&account.address(), &create_nonce);

  for (i, calldata) in std::env::args().skip(1).enumerate() {
    block.push_transaction(ethcore::transaction::Transaction {
      action    : ethcore::transaction::Action::Call(address),
      data      : calldata.from_hex().unwrap(),
      value     : U256::from(0),
      gas       : U256::from("ffffffffffff"),
      gas_price : U256::from(0),
      nonce     : nonce + U256::from(lines.len() + i),
    }.sign(&account.secret(), None), None).unwrap();
  }

  let fake_seal = vec![];
  client.import_sealed_block(
    block.close_and_lock().seal(&*genesis.engine, fake_seal).unwrap()
  ).unwrap();

  println!("{}", json::Value::Array((0 .. std::env::args().len()).map(|i| {
    match client.replay(
      ethcore::client::TransactionID::Location(
        ethcore::client::BlockID::Pending, i
      ),
      ethcore::client::CallAnalytics {
        transaction_tracing : true,
        vm_tracing          : false,
        state_diffing       : false,
      },
    ).unwrap() {
      ethcore::client::Executed {
        trace, logs, output, ..
      } => {
        let mut fields = json::Map::new();

        fields.insert("output".to_string(), {
          json::Value::String(output.to_hex())
        });

        fields.insert("success".to_string(), {
          json::Value::Bool(match trace[0].result {
            ethcore::trace::trace::Res::Call(_) => true,
            ethcore::trace::trace::Res::Create(_) => true,
            _ => false,
          })
        });

        fields.insert("logs".to_string(), {
          json::Value::Array(logs.iter().map(|log| {
            let mut fields = json::Map::new();

            fields.insert("address".to_string(), {
              json::Value::String(log.address.to_vec().to_hex())
            });
            fields.insert("data".to_string(), {
              json::Value::String(log.data.to_hex())
            });
            fields.insert("topics".to_string(), {
              json::Value::Array(log.topics.iter().map(|topic| {
                json::Value::String(topic.to_vec().to_hex())
              }).collect())
            });

            json::Value::Object(fields)
          }).collect())
        });

        fields.insert("trace".to_string(), {
          json::Value::Array(trace.iter().map(|item| {
            let mut fields = json::Map::new();

            fields.insert("action".to_string(), {
              let mut fields = json::Map::new();

              match item.action {
                ethcore::trace::trace::Action::Create(
                  ethcore::trace::trace::Create {
                    from, value, ref init, ..
                  }
                ) => {
                  fields.insert("type".to_string(), {
                    json::Value::String("create".to_string())
                  });
                  fields.insert("from".to_string(), {
                    json::Value::String(from.to_vec().to_hex())
                  });
                  fields.insert("value".to_string(), {
                    json::Value::String(value.to_string())
                  });
                  fields.insert("init".to_string(), {
                    json::Value::String(init.to_vec().to_hex())
                  });
                }

                ethcore::trace::trace::Action::Call(
                  ethcore::trace::trace::Call {
                    from, to, value, ref input, ref call_type, ..
                  }
                ) => {
                  fields.insert("type".to_string(), {
                    json::Value::String("call".to_string())
                  });
                  fields.insert("from".to_string(), {
                    json::Value::String(from.to_vec().to_hex())
                  });
                  fields.insert("to".to_string(), {
                    json::Value::String(to.to_vec().to_hex())
                  });
                  fields.insert("value".to_string(), {
                    json::Value::String(value.to_string())
                  });
                  fields.insert("input".to_string(), {
                    json::Value::String(input.to_vec().to_hex())
                  });
                  fields.insert("call_type".to_string(), {
                    json::Value::String(format!("{:?}", call_type))
                  });
                }

                ethcore::trace::trace::Action::Suicide(_) => {
                  fields.insert("type".to_string(), {
                    json::Value::String("suicide".to_string())
                  });
                }
              };

              json::Value::Object(fields)
            });

            fields.insert("result".to_string(), {
              let mut fields = json::Map::new();

              match item.result {
                ethcore::trace::trace::Res::Create(
                  ethcore::trace::trace::CreateResult {
                    address, ref code, ..
                  }
                ) => {
                  fields.insert("address".to_string(), {
                    json::Value::String(address.to_hex().to_string())
                  });
                  fields.insert("code".to_string(), {
                    json::Value::String(code.to_vec().to_hex().to_string())
                  });
                }

                ethcore::trace::trace::Res::Call(
                  ethcore::trace::trace::CallResult { ref output, .. }
                ) => {
                  fields.insert("output".to_string(), {
                    json::Value::String(output.to_hex().to_string())
                  });
                }

                ethcore::trace::trace::Res::FailedCall(ref error) => {
                  fields.insert("error".to_string(), {
                    json::Value::String(format!("{:?}", error))
                  });
                }

                ethcore::trace::trace::Res::FailedCreate(ref error) => {
                  fields.insert("error".to_string(), {
                    json::Value::String(format!("{:?}", error))
                  });
                }

                ethcore::trace::trace::Res::None => {
                  fields.insert("error".to_string(), {
                    json::Value::String("(none)".to_string())
                  });
                }
              }

              json::Value::Object(fields)
            });

            fields.insert("subtraces".to_string(), {
              json::Value::String(item.subtraces.to_string())
            });

            fields.insert("trace_address".to_string(), {
              json::Value::Array(item.trace_address.iter().map(|x| {
                json::Value::String(x.to_string())
              }).collect())
            });

            json::Value::Object(fields)
          }).collect())
        });

        json::Value::Object(fields)
      }
    }
  }).collect()))
}
