//! Asking a crypto wallet to sign or approve: what a dapp does, and what a
//! drainer hidden in a dependency does. A project's own signing warns; an
//! unlimited allowance, installed code, or signing in obfuscated code
//! fails. A bare `approve(` counts only with a wallet library beside it,
//! or an unlimited amount.

use super::{Context, Kind, Suspect, has_any, line_of, push};

pub(super) const ID: &str = "SUSPECT-WALLET-SIGNING";

/// Calls that sign, approve or connect.
const SIGNS: &[&str] = &[
    "approve(",
    "eth_signTypedData",
    "signTypedData",
    "personal_sign",
    "eth_sendTransaction",
    "setApprovalForAll",
    "increaseAllowance",
    "signAllTransactions",
    "signAndSendTransaction",
    "signTransaction(",
    "permit(",
    "Permit2",
    "eth_requestAccounts",
];
/// Wallet providers and libraries.
const WALLETS: &[&str] = &[
    "window.ethereum",
    "window.solana",
    "window.phantom",
    "ethereum.request",
    "solana.connect",
    "WalletConnect",
    "wagmi",
    "ethers",
    "viem",
    "@solana/web3",
    "web3",
];
/// An allowance of everything, however it is spelled.
const UNLIMITED: &[&str] =
    &["MaxUint256", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "2 ** 256", "2n ** 256n"];
/// The obfuscation findings that make signing a drainer.
const OBFUSCATION_IDS: &[&str] =
    &["SUSPECT-EXEC-DECODED", "SUSPECT-ENCODED-PAYLOAD", "SUSPECT-STRING-DECODER", "SUSPECT-ESCAPED-SOURCE"];

pub(super) fn scan(file: &str, text: &str, ctx: Context, kind: Kind, out: &mut Vec<Suspect>) {
    if !matches!(ctx, Context::Web | Context::Markup) {
        return;
    }
    let Some(s) = has_any(text, SIGNS) else { return };
    let unlimited = UNLIMITED.iter().any(|u| text.contains(u));
    let wallet = WALLETS.iter().any(|w| text.contains(w));
    if !wallet && !(s == "approve(" && unlimited) {
        return;
    }
    let obfuscated = out.iter().any(|o| OBFUSCATION_IDS.contains(&o.id));
    push(
        out,
        file,
        ID,
        line_of(text, s),
        format!(
            "asks a crypto wallet to sign or approve (`{}`){}{}{}",
            s.trim_end_matches('('),
            if unlimited { ", with an unlimited allowance" } else { "" },
            if obfuscated { ", in obfuscated code" } else { "" },
            if kind == Kind::Installed { ", from installed code rather than the project's own" } else { "" }
        ),
        obfuscated || kind == Kind::Installed || unlimited,
    );
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
            "only web code is read"
        );
        assert!(scan_text("docs/wallets.md", DAPP, Kind::Repo).is_empty());
        assert!(
            scan_text("src/pay.ts", "import { ethers } from 'ethers';\nprovider.getBalance(a);\n", Kind::Repo)
                .is_empty(),
            "a library without a signing call"
        );
    }
}
