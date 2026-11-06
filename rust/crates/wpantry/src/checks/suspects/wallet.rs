//! Asking a crypto wallet to sign or approve: what a dapp does, and what a
//! drainer hidden in a dependency does. A project's own signing warns; an
//! unlimited allowance, an operation that hands the account over (a Tron
//! permission update, an XRP regular key, a Stellar master weight, a
//! Solana authority change, an EVM or Tempo key authorization), installed
//! code, obfuscated code, or addresses of two or more chains hardcoded
//! beside the signing fails. A bare `approve(` counts only with a wallet
//! library beside it, or an unlimited amount. The chains read: Ethereum
//! and the EVM chains (BSC, Polygon, Tempo), Solana, Stellar, the XRP
//! Ledger and Tron.

use super::{Context, Kind, Suspect, has_any, line_of, push, test_path};
use crate::utils::addresses;

pub(super) const ID: &str = "SUSPECT-WALLET-SIGNING";

/// Calls that sign, approve or connect, on any chain.
const SIGNS: &[&str] = &[
    // EVM: Ethereum, BSC, Polygon, Tempo
    "approve(",
    "eth_signTypedData",
    "signTypedData",
    "personal_sign",
    "eth_sendTransaction",
    "setApprovalForAll",
    "increaseAllowance",
    "permit(",
    "Permit2",
    "eth_requestAccounts",
    "wallet_sendCalls",
    "wallet_grantPermissions",
    // Every chain's wallets
    "signMessage(",
    "signTransaction(",
    "signAllTransactions",
    "signAndSendTransaction",
    // Solana
    "signAndSendAllTransactions",
    "solana_signTransaction",
    "solana_signAllTransactions",
    "solana_signMessage",
    "createApproveInstruction",
    "approveChecked(",
    // Stellar
    "signAuthEntry",
    "signBlob(",
    "stellar_signXDR",
    "stellar_signAndSubmitXDR",
    // XRP Ledger
    "submitAndWait(",
    "xrpl_signTransaction",
    "sign_and_submit(",
    // Tron
    "tron_requestAccounts",
    "tron_signTransaction",
    "tron_signMessage",
    "signMessageV2",
    "trx.sign(",
    "multiSign(",
    "triggerSmartContract(",
];
/// Wallet providers and libraries.
const WALLETS: &[&str] = &[
    // EVM
    "window.ethereum",
    "ethereum.request",
    "WalletConnect",
    "wagmi",
    "ethers",
    "viem",
    "web3",
    // Solana
    "window.solana",
    "window.phantom",
    "window.solflare",
    "window.backpack",
    "solana.connect",
    "@solana/web3",
    "@solana/wallet-adapter",
    "@solana/kit",
    "@solana/spl-token",
    "solders",
    // Stellar
    "@stellar/stellar-sdk",
    "stellar-sdk",
    "stellar_sdk",
    "@stellar/freighter-api",
    "freighterApi",
    "window.freighter",
    "stellar-wallets-kit",
    // XRP Ledger
    "xrpl",
    "ripple-lib",
    "xumm",
    "@gemwallet/api",
    "@crossmarkio/sdk",
    // Tron
    "tronweb",
    "TronWeb",
    "tronWeb",
    "tronLink",
    "tronpy",
    // Tempo
    "viem/tempo",
];
/// An allowance of everything, however it is spelled.
const UNLIMITED: &[&str] =
    &["MaxUint256", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "2 ** 256", "2n ** 256n"];
/// (needle, chain, what it does): an operation that hands the account
/// itself over, rather than spending from it. One of these beside a
/// signing call or a wallet library fails outright.
const TAKEOVERS: &[(&str, &str, &str)] = &[
    ("AuthorityType.AccountOwner", "Solana", "reassigns a token account's owner"),
    ("AuthorityType.CloseAccount", "Solana", "takes a token account's close authority"),
    ("createSetAuthorityInstruction", "Solana", "changes an account's authority"),
    ("SystemProgram.assign", "Solana", "reassigns an account to another program"),
    ("accountMerge(", "Stellar", "merges the account into another, sending everything it holds"),
    ("masterWeight", "Stellar", "changes the master key's weight (at 0 the account is handed over)"),
    ("SetRegularKey", "XRP Ledger", "sets a regular key that signs for the account"),
    ("SignerListSet", "XRP Ledger", "replaces the account's signer list"),
    ("asfDisableMaster", "XRP Ledger", "disables the account's master key"),
    ("AccountDelete", "XRP Ledger", "deletes the account and sends its XRP away"),
    ("AccountPermissionUpdateContract", "Tron", "rewrites the account's owner and active permissions"),
    ("updateAccountPermissions", "Tron", "rewrites the account's owner and active permissions"),
    ("signAuthorization(", "EVM", "delegates the account to contract code (EIP-7702)"),
    (
        "0xAAAAAAAA00000000000000000000000000000000",
        "Tempo",
        "calls the Account Keychain precompile (adds a key to the account)",
    ),
    ("accessKey.authorize", "Tempo", "authorizes an access key on the account"),
    ("keyAuthorization", "Tempo", "carries an access-key authorization"),
];
/// The obfuscation findings that make signing a drainer.
const OBFUSCATION_IDS: &[&str] =
    &["SUSPECT-EXEC-DECODED", "SUSPECT-ENCODED-PAYLOAD", "SUSPECT-STRING-DECODER", "SUSPECT-ESCAPED-SOURCE"];

pub(super) fn scan(file: &str, text: &str, ctx: Context, kind: Kind, out: &mut Vec<Suspect>) {
    let web = matches!(ctx, Context::Web | Context::Markup);
    if !web && ctx != Context::Python {
        return;
    }
    let takeover = TAKEOVERS.iter().find(|(n, ..)| text.contains(n));
    let wallet = WALLETS.iter().any(|w| text.contains(w));
    let unlimited = UNLIMITED.iter().any(|u| text.contains(u));
    let sign = has_any(text, SIGNS);
    // Python is read only for a takeover with a chain library: its signing
    // is server-side, not a wallet prompt.
    let s = match (web, sign, takeover) {
        (false, _, Some((n, ..))) if wallet => *n,
        (false, ..) => return,
        (true, Some(s), _) if wallet || takeover.is_some() || (s == "approve(" && unlimited) => s,
        (true, None, Some((n, ..))) if wallet => *n,
        (true, ..) => return,
    };
    let chains = if test_path(file) { Vec::new() } else { addresses::chains_in(text) };
    let obfuscated = out.iter().any(|o| OBFUSCATION_IDS.contains(&o.id));
    let hard = obfuscated || kind == Kind::Installed || unlimited || takeover.is_some() || chains.len() >= 2;
    let mut note = format!("asks a crypto wallet to sign or approve (`{}`)", s.trim_end_matches('('));
    if unlimited {
        note.push_str(", with an unlimited allowance");
    }
    if let Some((n, chain, what)) = takeover {
        if *n != s {
            note.push_str(&format!(", and {what} (`{}`, {chain})", n.trim_end_matches('(')));
        } else {
            note.push_str(&format!(", which {what} ({chain})"));
        }
    }
    if !chains.is_empty() {
        note.push_str(&format!(
            ", with {} address{} hardcoded",
            chains.iter().map(|c| c.name()).collect::<Vec<_>>().join(" and "),
            if chains.len() == 1 { "" } else { "es" }
        ));
    }
    if obfuscated {
        note.push_str(", in obfuscated code");
    }
    if kind == Kind::Installed {
        note.push_str(", from installed code rather than the project's own");
    }
    push(out, file, ID, line_of(text, s), note, hard);
}

#[cfg(test)]
#[path = "wallet_tests.rs"]
mod tests;
