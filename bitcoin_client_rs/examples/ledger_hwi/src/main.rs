use std::str::FromStr;
use std::sync::Arc;
use std::{collections::BTreeMap, error::Error};

use bitcoin::absolute;
use bitcoin::bip32::DerivationPath;
use bitcoin::psbt::{Input, PsbtSighashType};
use bitcoin::script::Builder;
use bitcoin::{
    bip32::{self, ExtendedPubKey},
    hashes::hex::FromHex,
    key::TweakedPublicKey,
    psbt::Psbt,
    secp256k1::Secp256k1,
    taproot::TapTweakHash,
    Amount, OutPoint, Script, Transaction, TxIn, TxOut, Txid, Witness,
};

use hidapi::HidApi;
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
    let mut xpk: bip32::ExtendedPubKey = client.get_extended_pubkey(&path, false).await.unwrap();
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
        let add1 = get_address_public_key_by_path(&client, &format!("m{}", p1))
            .await
            .unwrap();

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
        Txid::from_str("9e0500bba9519c8b92deaf1ff8243fd509b14ea47b734713bd8a551393c42973").unwrap();
    let input_tx_index = 1;
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

    let ty = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(add1.to_x_only_pub());
    psbt.inputs = vec![input];

    let res: Vec<_> = client
        .sign_psbt(&psbt, &wallet, Some(&hmac))
        .await
        .map_err(|e| format!("{:#?}", e))
        .unwrap();
}
