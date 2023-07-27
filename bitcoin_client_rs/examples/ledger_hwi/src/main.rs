use std::convert::TryInto;
use std::str::FromStr;
use std::sync::Arc;
use std::{collections::BTreeMap, error::Error};

use bitcoin::bip32::DerivationPath;
use bitcoin::psbt::{Input, PsbtSighashType};
use bitcoin::script::Builder;
use bitcoin::{absolute, taproot, Network};
use bitcoin::{
    bip32::{self, ExtendedPubKey},
    hashes::hex::FromHex,
    key::TweakedPublicKey,
    psbt::Psbt,
    secp256k1::Secp256k1,
    taproot::TapTweakHash,
    Amount, OutPoint, Script, Transaction, TxIn, TxOut, Txid, Witness,
};

use bitcoincore_rpc::{Auth, Client};
use bitcoincore_rpc::{RawTx, RpcApi};
use hidapi::HidApi;
use ledger_bitcoin_client::psbt::PartialSignatureError;
use ledger_transport_hid::TransportNativeHID;
use regex::Regex;

use ledger_bitcoin_client::{
    async_client::{BitcoinClient, Transport},
    psbt::PartialSignature,
    wallet::{self, Version, WalletPolicy, WalletPubKey},
};

mod transport;
use transport::{TransportHID, TransportTcp, TransportWrapper};

use clap::{Parser, Subcommand};

async fn get_default_client() -> BitcoinClient<TransportWrapper> {
    let transport: Arc<dyn Transport<Error = Box<dyn Error>> + Send + Sync> = {
        if let Ok(transport) = TransportTcp::new().await {
            Arc::new(transport)
        } else {
            Arc::new(TransportHID::new(
                TransportNativeHID::new(&HidApi::new().expect("unable to get HIDAPI")).unwrap(),
            ))
        }
    };

    let client = BitcoinClient::new(TransportWrapper::new(transport));

    {
        let version = client.get_version().await.unwrap();
        println!("version {:?}", version);
    }
    client
}

async fn get_address_public_key_by_path(
    client: &BitcoinClient<TransportWrapper>,
    path: &str,
) -> anyhow::Result<bip32::ExtendedPubKey> {
    let path = bip32::DerivationPath::from_str(path)
        .map_err(|e| format!("{}", e))
        .unwrap();
    let mut xpk: bip32::ExtendedPubKey = client.get_extended_pubkey(&path, true).await.unwrap();
    xpk.network = bitcoin::Network::Bitcoin;
    println!("ad {}", xpk.to_string());
    xpk.network = bitcoin::Network::Regtest;
    println!("ad {}", xpk.to_string());
    let pp = xpk.to_pub();
    println!("to_x_only_pub {} ", xpk.to_x_only_pub());
    println!("to_x_only_pub to pub  {}", pp);
    Ok(xpk)
}

fn get_address(xpk: ExtendedPubKey) -> bitcoin::Address {
    // 1p
    let pub_x_key = xpk.to_x_only_pub();

    let tth = TapTweakHash::from_key_and_tweak(pub_x_key, None);
    let tweak = tth.to_scalar();
    let (pp1_x, _) = pub_x_key.add_tweak(&Secp256k1::new(), &tweak).unwrap();

    let pp = TweakedPublicKey::dangerous_assume_tweaked(pp1_x);

    // 1p
    let p2tr = bitcoin::Address::p2tr_tweaked(pp, bitcoin::Network::Regtest);
    println!(
        "address p2tr {} , publi_key_x {}, pre {} ",
        p2tr, pp1_x, pub_x_key
    );
    p2tr
}

async fn registe_wallet(
    p1: &str,
    keys: Vec<&str>,
    client: &BitcoinClient<TransportWrapper>,
) -> anyhow::Result<([u8; 32], [u8; 32], WalletPolicy)> {
    let mut keys_str = vec![];

    let fg = client.get_master_fingerprint().await.unwrap();

    for itr in keys {
        // 地址
        let mut add1 = get_address_public_key_by_path(&client, &format!("m{}", p1))
            .await
            .unwrap();
        add1.network = Network::from_core_arg("main")?;
        let kk = format!("[{}{}]{}", fg, p1, add1);
        println!("registe key {}", kk);
        keys_str.push(kk);
    }

    let keysr: Vec<wallet::WalletPubKey> = keys_str
        .iter()
        .map(|s| wallet::WalletPubKey::from_str(s).unwrap())
        .collect();

    let wallet = WalletPolicy::new(
        "test wallet".to_string(),
        Version::V2,
        "tr(@0/**)".to_string(),
        keysr,
    );

    let (r1, r2) = client.register_wallet(&wallet).await.unwrap();
    return Ok((r1, r2, wallet));
}

#[tokio::main]
async fn main() {
    let root_path = "/86'/1'/0'";
    let d1_address_path = "m/86'/1'/0'/0/0";
    let client = get_default_client().await;

    let fp_pp = client.get_master_fingerprint().await.unwrap();

    let add1 = get_address_public_key_by_path(&client, d1_address_path)
        .await
        .unwrap();

    let input_address = get_address(add1);
    println!(
        "input address {}, pub {:x}",
        input_address.to_string(),
        add1.to_x_only_pub()
    );

    let input_value = Amount::ONE_BTC * 10;
    let to_value = input_value.to_sat() - 10159 - 50000;

    let input_hash =
        Txid::from_str("00413ed34a77f93ef2dbfd7d4b4272c22e1fa450ac0e10cb4503a8aa41a017b8").unwrap();
    let input_tx_index = 0;
    let (hmac, wallet) = {
        let (_, hmac, wa) = registe_wallet(root_path, vec![d1_address_path], &client)
            .await
            .unwrap();
        (hmac, wa)
    };

    let vout: Vec<TxOut> = vec![
        TxOut {
            value: 10159,
            script_pubkey: input_address.script_pubkey(),
        },
        TxOut {
            value: to_value,
            script_pubkey: input_address.script_pubkey(),
        },
    ];

    let tx1 = Transaction {
        version: 2,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_hash,
                vout: input_tx_index,
            },
            script_sig: Builder::new().into_script(),
            sequence: bitcoin::Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        }],
        output: vout,
    };

    let mut psbt: bitcoin::psbt::PartiallySignedTransaction = Psbt::from_unsigned_tx(tx1).unwrap();

    let mut origins = BTreeMap::new();

    origins.insert(
        add1.to_x_only_pub(),
        (
            vec![],
            (fp_pp, DerivationPath::from_str(d1_address_path).unwrap()),
        ),
    );

    let mut input = Input {
        witness_utxo: {
            Some(TxOut {
                value: input_value.to_sat(),
                script_pubkey: input_address.script_pubkey(),
            })
        },
        tap_key_origins: origins,
        ..Default::default()
    };

    let ty = PsbtSighashType::from_str("SIGHASH_DEFAULT").unwrap();
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(add1.to_x_only_pub());
    psbt.inputs = vec![input];

    let psbt_str = serde_json::to_string(&psbt).unwrap();
    println!("{}", psbt_str);

    println!("wallet desc {}", wallet.get_descriptor(false).unwrap());

    let res = client.sign_psbt(&psbt, &wallet, Some(&hmac)).await;
    if res.is_err() {
        println!("result error {:?}", res.err().unwrap());
    } else {
        for (index, sig) in res.unwrap() {
            match sig {
                PartialSignature::Sig(pub_key, ss) => {
                    println!("index {}, pub {} sig {}", index, pub_key, ss);
                }
                PartialSignature::TapScriptSig(x_pub, leaf_hash, sig) => {
                    println!("x pub {}", x_pub);
                    println!("x sig {}", sig.sig);
                    println!("x leaf hash {:?}", leaf_hash);

                    let mut script_witness: Witness = Witness::new();
                    script_witness.push(&sig.sig.as_ref().to_vec());
                    // script_witness.push(x_pub.serialize());

                    psbt.inputs[index].final_script_witness = Some(script_witness)
                }
            }
        }
    }

    use bitcoin::consensus::encode;

    use bitcoincore_rpc::RpcApi;

    let tx = psbt.extract_tx();

    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("admin".to_string(), "123456".to_string()),
    )
    .unwrap();
    println!("send tx json {}", serde_json::to_string(&tx).unwrap());

    let hex_data = tx.raw_hex();
    println!("hex data {}", hex_data);
    let send_ret = rpc.send_raw_transaction(&tx);
    println!("{:?}", send_ret);
}

#[test]
fn test_data() {
    let dd = hex::decode("4584101aa2073c82c0387f5f2694c627962bbb19e7b224036ed5269148e4dfd196f01cd29d4ef2db510d897635e2718c20dbf08f4d28482eef15fc812a5515ad2f4f04bd886fe80ba322be3b032225f827b02c189c29276b9d0f1af60fe9131c01").unwrap();
    let r = &dd[32..];
    println!("result r {}", hex::encode(r));

    let sig = taproot::Signature::from_slice(&dd[33..]).unwrap();
    println!("sig {:x}", sig.sig);
}

#[tokio::test]
async fn test_registe_wallet() {
    let root_path = "/86'/1'/0'";
    let d1_address_path = "m/86'/1'/0'/0/0";
    let client = get_default_client().await;

    let (_, hmac, wa) = registe_wallet(root_path, vec![d1_address_path], &client)
        .await
        .unwrap();
}

#[test]
fn test_get_tx() {
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("admin".to_string(), "123456".to_string()),
    )
    .unwrap();

    let tx_id =
        bitcoin::Txid::from_str("7284ccf0682ef7052a4eb01727255433d54f3e708678f678c0fad084b0c5a38a")
            .unwrap();
    let tx = rpc.get_raw_transaction(&tx_id, None).unwrap();

    println!("send tx json {}", serde_json::to_string(&tx).unwrap());
}
