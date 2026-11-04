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
mod tests {
    use super::super::{Kind, ids, scan_text};

    const DAPP: &str =
        "import { ethers } from 'ethers';\nconst sig = await signer.signTypedData(domain, types, value);\n";

    #[test]
    fn a_dapps_own_signing_warns() {
        let got = scan_text("src/swap.ts", DAPP, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", false)], "a dapp's own code warns");
        assert_eq!(got[0].line, 2);
        assert_eq!(got[0].note, "asks a crypto wallet to sign or approve (`signTypedData`)");
        let page = "<script>window.ethereum.request({ method: 'eth_requestAccounts' })</script>";
        assert_eq!(ids(&scan_text("index.html", page, Kind::Repo)), [("SUSPECT-WALLET-SIGNING", false)]);
    }

    #[test]
    fn unlimited_installed_or_obfuscated_signing_fails() {
        let drainer = "import { ethers } from 'ethers';\nawait token.approve(spender, ethers.MaxUint256);\n";
        let got = scan_text("src/swap.ts", drainer, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)], "unlimited allowance fails");
        assert!(got[0].note.contains("(`approve`), with an unlimited allowance"), "{}", got[0].note);
        let bare = "await token.approve(spender, 2n ** 256n - 1n);\n";
        assert_eq!(
            ids(&scan_text("src/x.js", bare, Kind::Repo)),
            [("SUSPECT-WALLET-SIGNING", true)],
            "no library named, but unlimited"
        );
        let got = scan_text("ext/content.js", DAPP, Kind::Installed);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)], "installed code fails");
        assert!(got[0].note.ends_with(", from installed code rather than the project's own"), "{}", got[0].note);
        let obf = format!("{DAPP}eval(atob('eA=='));\n");
        let got = scan_text("src/swap.ts", &obf, Kind::Repo);
        assert!(ids(&got).contains(&("SUSPECT-WALLET-SIGNING", true)), "{got:?}");
        assert!(got.iter().any(|s| s.note.contains(", in obfuscated code")), "{got:?}");
    }

    #[test]
    fn approve_without_a_wallet_is_any_other_approve() {
        assert!(
            scan_text("src/review.js", "await pr.approve(id);\n", Kind::Repo).is_empty(),
            "approve is a common verb"
        );
        assert_eq!(
            ids(&scan_text("src/review.js", "await pr.approve(id); const max = 'MaxUint256';\n", Kind::Repo)),
            [("SUSPECT-WALLET-SIGNING", true)],
            "unlimited beside a bare approve is the drainer shape"
        );
        assert!(scan_text("src/perms.js", "grant.permit(user);\n", Kind::Repo).is_empty());
        assert!(
            scan_text("wallet.py", "web3.eth.sendTransaction(tx)\nsigner.signTransaction(tx)\n", Kind::Repo).is_empty(),
            "only web code is read for plain signing"
        );
        assert!(scan_text("docs/wallets.md", DAPP, Kind::Repo).is_empty());
        assert!(
            scan_text("src/pay.ts", "import { ethers } from 'ethers';\nprovider.getBalance(a);\n", Kind::Repo)
                .is_empty(),
            "a library without a signing call"
        );
    }

    #[test]
    fn other_chains_sign_the_same_way() {
        let sol = "import { useWallet } from '@solana/wallet-adapter-react';\nconst signed = await signAllTransactions(txs);\n";
        let got = scan_text("src/mint.tsx", sol, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", false)], "Solana: {got:?}");
        assert!(got[0].note.contains("`signAllTransactions`"));
        let xlm = "import freighterApi from '@stellar/freighter-api';\nconst { signedTxXdr } = await freighterApi.signTransaction(xdr, { networkPassphrase });\n";
        assert_eq!(ids(&scan_text("src/pay.ts", xlm, Kind::Repo)), [("SUSPECT-WALLET-SIGNING", false)], "Stellar");
        let xrp = "import { Client, Wallet } from 'xrpl';\nawait client.submitAndWait(tx, { wallet });\n";
        assert_eq!(ids(&scan_text("src/xrp.ts", xrp, Kind::Repo)), [("SUSPECT-WALLET-SIGNING", false)], "XRP");
        let trx = "const res = await window.tronLink.request({ method: 'tron_requestAccounts' });\nconst s = await tronWeb.trx.sign(tx);\n";
        assert_eq!(ids(&scan_text("src/tron.js", trx, Kind::Repo)), [("SUSPECT-WALLET-SIGNING", false)], "Tron");
        let tempo =
            "import { Account } from 'viem/tempo';\nconst sig = await client.signMessage({ account, message });\n";
        assert_eq!(ids(&scan_text("src/tempo.ts", tempo, Kind::Repo)), [("SUSPECT-WALLET-SIGNING", false)], "Tempo");
        let auth = "import { Account } from 'viem/tempo';\nawait client.accessKey.authorize({ accessKey, expiry });\n";
        let got = scan_text("src/keys.ts", auth, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)], "an access key hands the account over");
        assert!(got[0].note.contains("authorizes an access key on the account (Tempo)"), "{}", got[0].note);
    }

    #[test]
    fn handing_the_account_over_fails() {
        let tron = "const tx = await tronWeb.transactionBuilder.updateAccountPermissions(owner, ownerPerm, witness, actives);\nawait tronWeb.trx.sign(tx);\n";
        let got = scan_text("src/perm.js", tron, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)], "{got:?}");
        assert!(
            got[0]
                .note
                .contains("rewrites the account's owner and active permissions (`updateAccountPermissions`, Tron)"),
            "{}",
            got[0].note
        );
        let xrp = "import { Client } from 'xrpl';\nconst tx = { TransactionType: 'SetRegularKey', Account: a, RegularKey: mine };\nawait client.submitAndWait(tx, { wallet });\n";
        let got = scan_text("src/key.ts", xrp, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)]);
        assert!(
            got[0].note.contains("sets a regular key that signs for the account (`SetRegularKey`, XRP Ledger)"),
            "{}",
            got[0].note
        );
        let xlm = "import { Operation } from '@stellar/stellar-sdk';\ntx.addOperation(Operation.setOptions({ masterWeight: 0, signer: { ed25519PublicKey: mine, weight: 1 } }));\nawait freighterApi.signTransaction(tx.toXDR());\n";
        assert_eq!(
            ids(&scan_text("src/take.ts", xlm, Kind::Repo)),
            [("SUSPECT-WALLET-SIGNING", true)],
            "Stellar master weight"
        );
        let sol = "import { createSetAuthorityInstruction, AuthorityType } from '@solana/spl-token';\ntx.add(createSetAuthorityInstruction(ata, owner, AuthorityType.AccountOwner, mine));\nawait signAllTransactions([tx]);\n";
        let got = scan_text("src/own.ts", sol, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)]);
        assert!(
            got[0].note.contains("reassigns a token account's owner (`AuthorityType.AccountOwner`, Solana)"),
            "{}",
            got[0].note
        );
        let evm = "import { createWalletClient } from 'viem';\nconst authorization = await client.signAuthorization({ contractAddress });\n";
        let got = scan_text("src/delegate.ts", evm, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)], "EIP-7702: {got:?}");
        assert!(
            got[0].note.contains("which delegates the account to contract code (EIP-7702) (EVM)"),
            "{}",
            got[0].note
        );
        let py = "from tronpy import Tron\ntxn = client.trx.account_permission_update(owner, perms)\n# AccountPermissionUpdateContract\n";
        let got = scan_text("take.py", py, Kind::Repo);
        assert_eq!(
            ids(&got),
            [("SUSPECT-WALLET-SIGNING", true)],
            "Python with a chain library and a takeover: {got:?}"
        );
        assert!(
            scan_text("types.py", "class AccountPermissionUpdateContract: pass\n", Kind::Repo).is_empty(),
            "no library, no finding"
        );
        assert!(
            scan_text("src/types.ts", "export type TxType = 'SetRegularKey' | 'Payment';\n", Kind::Repo).is_empty(),
            "a type alone, no wallet, no signing"
        );
    }

    #[test]
    fn hardcoded_addresses_on_two_chains_fail() {
        let one = "import { ethers } from 'ethers';\nconst FEE_TO = '0xdAC17F958D2ee523a2206206994597C13D831ec7';\nawait signer.signTypedData(d, t, v);\n";
        let got = scan_text("src/fee.ts", one, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", false)], "one chain's treasury address is a dapp's");
        assert!(got[0].note.ends_with("with EVM (Ethereum, BSC, Tempo) address hardcoded"), "{}", got[0].note);
        let two = "import { ethers } from 'ethers';\nconst OUT = { eth: '0xdAC17F958D2ee523a2206206994597C13D831ec7', trx: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', sol: '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM' };\nawait signer.signTypedData(d, t, v);\n";
        let got = scan_text("src/drain.ts", two, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-WALLET-SIGNING", true)], "{got:?}");
        assert!(
            got[0].note.contains("with EVM (Ethereum, BSC, Tempo) and Tron and Solana addresses hardcoded"),
            "{}",
            got[0].note
        );
        assert_eq!(
            ids(&scan_text("src/__tests__/drain.test.ts", two, Kind::Repo)),
            [("SUSPECT-WALLET-SIGNING", false)],
            "fixtures hold addresses"
        );
    }
}
