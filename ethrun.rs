/// ethrun.rs -- directly run Ethereum bytecode

extern crate ethcore;
extern crate ethcore_devtools;
extern crate ethcore_io;
extern crate ethcore_util;
extern crate ethstore;

use ethcore::account_provider::AccountProvider;
use ethcore::client::Client;
use ethcore_util::FromHex;

use std::sync::Arc;

fn main() {
  let SECRET   = "a100df7a048e50ed308ea696dc600215098141cb391e9527329df289f9383f65";
  let code     = "0102030405".from_hex();
  let calldata = "0102030405".from_hex();
  let path     = ethcore_devtools::RandomTempPath::new().as_path();
  let chain    = ethcore::spec::Spec::load(include_bytes!("./chain.json"));
  let miner    = Arc::new(ethcore::miner::Miner::with_spec(&chain));
  let conf     = ethcore::client::ClientConfig::default();
  let ionull   = ethcore_io::IoChannel::disconnected();
  let client   = Client::new(&conf, &chain, &path, &miner, &ionull).unwrap();
  let secret   = ethstore::ethkey::Secret::from_str(SECRET).unwrap();
  let provider = AccountProvider::transient_provider();
  let account  = provider.insert_account(secret.clone(), "").unwrap();
  let nonce    = client.latest_nonce(&account);
  let address  = ethcore::contract_address(&account, &nonce);

  provider.unlock_account_permanently(account, "".to_string()).unwrap();

  let what = (1.into(), 1_000_000.into());
  let mut block = client.prepare_open_block(account, what, vec![]);

  block.push_transaction(
    ethcore::transaction::Transaction {
      action    : ethcore::transaction::Action::Create,
      value     : ethcore_util::U256::from(0),
      data      : code.clone(),
      gas       : ethcore_util::U256::from(50_000_000),
      gas_price : ethcore_util::U256::one(),
      nonce     : client.latest_nonce(&account)
    }.sign(&secret), None
  ).unwrap();

  client.import_sealed_block(
    block.close_and_lock().seal(&*chain.engine, vec![]).unwrap()
  ).unwrap();

  client.flush_queue();

  match client.call(
    ethcore::transaction::Transaction {
      nonce     : client.latest_nonce(ethcore_util::Address::default()),
      action    : ethcore::transaction::Action::Call(address),
      gas       : ethcore_util::U256::from(50_000_000),
      gas_price : ethcore_util::U256::default(),
      value     : ethcore_util::U256::default(),
      data      : calldata,
    }.fake_sign(account), ethcore::client::BlockID::Latest
  ) {
    Ok((failed, ethcore::client::Executed { logs, .. })) => {
      println!("{}", logs);
    },
    Err(e) => {
      println!("ethrun: error: {:?}", e)
    }
  }
}
