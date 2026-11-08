# Create a token and a DAO on DarkFi

This is a beginner walkthrough. You will mint two tokens on a one-node localnet,
freeze one of them, deploy a DAO with the native DAO contract, put treasury funds
under DAO control, vote, and pay those funds out early.

**Two wallets:**

| Job | Tool |
| --- | --- |
| Mint tokens, create/mint a DAO, deploy/lock WASM, send DRK | **Moonshine** (`token` / `dao` / `contract` / `tx send`) or **`drk`** |
| Propose, vote, exec, DAO treasury spend-hooks | **`drk` only** (Moonshine lists synced DAO calls but does not vote/exec yet) |

The long command log below is from a real `drk` run on 31 October 2026 against
`darkfid` built from the DarkFi pin Moonshine uses (`nighthawk24/darkfi`, branch
`nighthawk-testnet`, commit `44ec78b6efbf1d3e797f99bffe95195994b2488d`). See
[darkfi-pin.md](darkfi-pin.md). A Moonshine 3.1.6 localnet path (token mint → DAO
mint → Deployooor deploy/lock through `darkfi-lightwalletd`) was verified on
7 November 2026.

Your token IDs, DAO bulla, addresses, and transaction IDs will be different.
Copy the commands. Treat the sample output as a picture of a successful run,
not as values to paste back in.

## What you end up with

| Thing | In this run |
| --- | --- |
| Governance token `ANON` | `C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U` (still mintable) |
| Treasury token `DAWN` | `2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S` (frozen) |
| DAO | `GuideDAO`, bulla `FzPGVLhKpUpEiZ4MLfir8BfDaEDMktW4tjAqkjE4QugE` |
| Treasury after the payout | 6 DAWN left in the DAO, 4 DAWN paid back to the wallet |

## Three different "contracts"

People say "deploy a contract" for three different jobs. Only the third one
uploads new code.

1. **Money** is already on the chain. A token is not a new contract. `token
   generate-mint` makes a mint-authority key, and the token ID is derived from
   that key. `token mint` asks the Money contract to create coins. `token freeze`
   burns the mint authority so nobody can mint that token again.
2. **DAO** is already on the chain too. `dao create` writes a parameter file on
   your computer. `dao mint` asks the DAO contract to commit that DAO on chain.
   After that, the DAO can hold coins and spend them only by an approved proposal.
3. **Your own WASM contract** is the Deployooor path: `contract generate-deploy`,
   `contract deploy`, then `contract lock`. A DAO does not need this. The last
   section shows the commands and stops there, because this walkthrough did not
   upload a custom binary.

## Words you will see

- **Atomic units.** You type amounts like `20` or `4`. The chain stores
  8 decimal places, so 20 is `2000000000` and 4 is `400000000`.
- **Alias.** A local nickname in your wallet (`ANON`, `DAWN`, `GuideDAO`).
  Other people do not see it. They see the token ID or the DAO bulla.
- **Bulla.** The public id of a DAO or of a proposal. It is a hash of the
  parameters, blinded so the parameters stay private until someone who holds
  the viewer keys opens them.
- **Spend hook and user data.** A coin can be marked "only this contract may
  spend me, and only for this DAO." The hook used here is the DAO exec function.
  The user data is the DAO bulla. Coins sent to the DAO address without that
  mark are not treasury the DAO can spend.
- **Block window.** Proposals measure time in windows, not in single blocks.
  On public testnet one window is about 4 hours. On a brand-new localnet the
  window index can stay `0` for the whole exercise, which is why this run uses
  early execution instead of waiting.
- **Fee.** Every broadcast spends a little DRK. Mine some DRK (localnet) or
  obtain some (testnet) before the first mint.

## 1. Run a one-node localnet

Use a directory that is only for this exercise. The ports below are `49340`–
`49347` so they do not collide with a normal DarkFi node (`28345`) or with
another localnet you already have.

`darkfid.toml`:

```toml
network = "localnet"

[network_config."localnet"]
database = "/path/to/dao-guide/darkfid"
threshold = 1
max_forks = 8
pow_target = 10
pow_fixed_difficulty = 1
skip_sync = true
skip_fees = false

[network_config."localnet".rpc]
rpc_listen = "tcp://127.0.0.1:49345"

[network_config."localnet".management_rpc]
rpc_listen = "tcp://127.0.0.1:49346"

[network_config."localnet".stratum_rpc]
rpc_listen = "tcp://127.0.0.1:49347"

[network_config."localnet".net]
localnet = true
active_profiles = ["tcp+tls"]

[network_config."localnet".net.profiles."tcp+tls"]
inbound = ["tcp+tls://127.0.0.1:49340"]
```

The inbound profile line matters. Without it, current `darkfid` exits with
`Active profile 'tcp+tls' not defined in net.profiles`.

`drk.toml`:

```toml
network = "localnet"

[network_config."localnet"]
cache_path = "/path/to/dao-guide/drk/cache"
wallet_path = "/path/to/dao-guide/drk/wallet.db"
wallet_pass = "choose-a-password"
endpoint = "tcp://127.0.0.1:49345"
history_path = "/path/to/dao-guide/drk/history.txt"
```

Start the node:

```bash
darkfid --config darkfid.toml
```

The rest of this page assumes:

```bash
drk --config drk.toml <command>
```

You can also start `drk --config drk.toml` with no command and type at the
`drk>` prompt. The prompt and the one-shot form run the same code.

### Wallet and mining

```bash
drk --config drk.toml wallet initialize
drk --config drk.toml wallet address
```

This run created:

```text
DXqLbrzhvi8Za3umAQT1A5LyUzoJthzCHjbDYunWrszsYEfvtkchMoNs
```

Point a miner at the stratum port and at that address. Any RandomX miner that
speaks the DarkFi stratum port works. One that ships with the Nighthawk desktop
tree is `xmrig`:

```bash
xmrig -o 127.0.0.1:49347 -u DXqLbrzhvi8Za3umAQT1A5LyUzoJthzCHjbDYunWrszsYEfvtkchMoNs -t 2
```

Leave it running in another terminal. `pow_fixed_difficulty = 1` makes blocks
arrive quickly on one machine. Stop the miner when you are done so it does not
keep the disk growing.

Then scan, and repeat the scan until DRK shows up:

```bash
drk --config drk.toml scan
drk --config drk.toml wallet balance
```

```text
 Token ID                                     | Aliases | Balance
----------------------------------------------+---------+---------
 241vANigf1Cy3ytjM1KHXiVECxgxdK4yApddL8KcLssb | DRK     | 80
```

`241vANigf1Cy3ytjM1KHXiVECxgxdK4yApddL8KcLssb` is the native DRK token id.
The balance will not stay at 80. This run mined through the later steps and
finished at 560 DRK after fees. Yours only needs to be high enough to pay fees.

`scan` is also how you confirm a transaction. Broadcast, wait for a block, scan
again. If a later command says the object is not deployed yet, scan again.
The chain had the object; the wallet had not indexed it.

## 2. Mint two tokens

`ANON` is the governance token. Holders vote with it. This run leaves it
unfrozen so more can be minted later.

`DAWN` is the treasury token. The DAO will hold it and pay it out. This run
freezes it so the supply cannot grow after the first mint.

On this pin, `token generate-mint` creates the mint-authority secret, stores
it in the wallet, and prints only the token ID. It does not print the secret.
Back up `wallet.db`. Anyone with that wallet can mint until you freeze.

```bash
drk --config drk.toml token generate-mint
```

Governance token in this run:

```text
Successfully imported mint authority for token ID: C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U
```

Treasury token:

```text
Successfully imported mint authority for token ID: 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S
```

`token list` shows the public mint authority and the token blind. Aliases are
still empty. `Freeze Height` stays `-` until you freeze.

```bash
drk --config drk.toml token list
```

```text
 Token ID                                     | Aliases | Mint Authority                               | Token Blind                                  | Frozen | Freeze Height
----------------------------------------------+---------+----------------------------------------------+----------------------------------------------+--------+---------------
 C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U | -       | 5GZ1jnbKvf3rsc5Cf8Rcj4dzW7uqdfDCLnvqooVwJEU7 | FmSsm6Fa7TGh75P76iA2TB8BCUzevEMu85cPbG4wXCzG | false  | -
 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S | -       | CvdjqzbQ2btLAQYwCee4A2QbKF64KmZfR2QYH8sa9WSr | 4BW38QsW2GBjWp9nrnQhYZkhgvo3VXjxfWrfh4YuLgKp | false  | -
```

Give each token a local name. The name is not written on chain.

```bash
drk --config drk.toml alias add ANON C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U
drk --config drk.toml alias add DAWN 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S
drk --config drk.toml alias show
```

```text
Generating alias ANON for Token: C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U
Generating alias DAWN for Token: 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S
```

```text
 Alias | Token ID
-------+----------------------------------------------
 DAWN  | 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S
 ANON  | C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U
 DRK   | 241vANigf1Cy3ytjM1KHXiVECxgxdK4yApddL8KcLssb
```

`token import <secret> <token-blind>` is the other way in. Use it when you
already have a mint secret and its blind from another wallet. This run did
not need it, because `generate-mint` imported the new keys itself.

Mint 40 ANON and 20 DAWN to your own address. `token mint` prints a transaction.
Pipe it to `broadcast`.

```bash
drk --config drk.toml token mint ANON 40 DXqLbrzhvi8Za3umAQT1A5LyUzoJthzCHjbDYunWrszsYEfvtkchMoNs \
  | drk --config drk.toml broadcast
```

```text
[mark_tx_spend] Processing transaction: 3e55cfe96d9ca4a717001818eaf9eaaa2f854e8a9fa6c39811116feca1439c18
[mark_tx_spend] Found Money contract in call 1
Broadcasting transaction...
Transaction ID: 3e55cfe96d9ca4a717001818eaf9eaaa2f854e8a9fa6c39811116feca1439c18
```

```bash
drk --config drk.toml token mint DAWN 20 DXqLbrzhvi8Za3umAQT1A5LyUzoJthzCHjbDYunWrszsYEfvtkchMoNs \
  | drk --config drk.toml broadcast
```

```text
Transaction ID: cfe0580f09a9ac8dd868396dda5213ed8860f91bac034030f9c3e14a3b6f22a4
```

Mine a block, then:

```bash
drk --config drk.toml scan
drk --config drk.toml wallet balance
```

```text
 Token ID                                     | Aliases | Balance
----------------------------------------------+---------+---------
 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S | DAWN    | 20
 C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U | ANON    | 40
 241vANigf1Cy3ytjM1KHXiVECxgxdK4yApddL8KcLssb | DRK     | 160
```

The piped form spends the transaction from stdin. If you would rather keep the
transaction, write it to a file and broadcast the file. Same bytes, same result:

```bash
drk --config drk.toml token mint DAWN 20 <your-address> > dawn-mint.tx
drk --config drk.toml broadcast < dawn-mint.tx
```

The printed transaction is large base64. You do not need to read it.

## 3. Freeze the treasury token

Freezing burns the mint authority. Do this only when the supply is final.
This run freezes `DAWN` and leaves `ANON` open.

```bash
drk --config drk.toml token freeze DAWN | drk --config drk.toml broadcast
```

```text
Transaction ID: fef90d00a647544fcb403ddd9bad679b6504be9d3265a021351b6fd636708df4
```

Scan, then `token list` shows `Frozen: true` for `DAWN`. In this run the
freeze height was 11, the same block that minted the DAO in the next step.

```text
 Token ID                                     | Aliases | Mint Authority                               | Token Blind                                  | Frozen | Freeze Height
----------------------------------------------+---------+----------------------------------------------+----------------------------------------------+--------+---------------
 C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U | ANON    | 5GZ1jnbKvf3rsc5Cf8Rcj4dzW7uqdfDCLnvqooVwJEU7 | FmSsm6Fa7TGh75P76iA2TB8BCUzevEMu85cPbG4wXCzG | false  | -
 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S | DAWN    | CvdjqzbQ2btLAQYwCee4A2QbKF64KmZfR2QYH8sa9WSr | 4BW38QsW2GBjWp9nrnQhYZkhgvo3VXjxfWrfh4YuLgKp | true   | 11
```

Another `token mint DAWN ...` after the freeze is rejected.

## 4. Write the DAO parameters

Pick limits before you mint. They are committed on chain and this wallet does
not edit them later.

This DAO:

| Parameter | Value | Meaning |
| --- | --- | --- |
| Proposer limit | 20 ANON | A proposer must hold at least 20 governance tokens. The chain stores `2000000000`. |
| Quorum | 10 ANON | At least 10 tokens must vote. Stored as `1000000000`. |
| Early-exec quorum | 10 ANON | Same bar, but the executor key may run the proposal before the window ends. Must be greater than or equal to quorum. |
| Approval ratio | 0.67 | Yes votes must be at least 67% of the votes cast. |
| Governance token | ANON | Votes are weighed by ANON, not by DAWN and not by DRK. |

`dao create` generates the keys and prints TOML. Save it.

```bash
drk --config drk.toml dao create 20 10 10 0.67 ANON > guide-dao.toml
```

The file holds secret keys. Do not commit it. `dao create` writes the comments
and the keys. Public values from this run are below. Secret lines are left as
placeholders so this page is not a key dump. Your file has the real secrets,
and your public keys will be different. The bulla blind is random.

```toml
proposer_limit = "20"
quorum = "10"
early_exec_quorum = "10"
approval_ratio = 0.67
gov_token_id = "C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U"
bulla_blind = "ATNM3RBasaacrf3nequr8trjDrPfUNR1NwZwqZAK8gCy"

notes_public_key = "9Shv7ND1KepownbzV2XBD3x97xNUqZXrAJ7AzL7nfTjR"
notes_secret_key = "<secret — leave the real line in your file>"
proposer_public_key = "7LWaRRKJqo512mpP7tvYwrp8UtfDw6C91MBq1bq2QGyW"
proposer_secret_key = "<secret — leave the real line in your file>"
proposals_public_key = "ApHgeWWLoXfeeuqJWnLp2wq1RyPp3MGDwHpuNqnpi9GM"
proposals_secret_key = "<secret — leave the real line in your file>"
votes_public_key = "6kS28P3xCzyaHoLBEUVjLkAanFxhD4WVGGaAA9zkHZqA"
votes_secret_key = "<secret — leave the real line in your file>"
exec_public_key = "5ZCyk29i2HA2F7qT1PY12KCcVqp3rmyqfGvQ79UckgwS"
exec_secret_key = "<secret — leave the real line in your file>"
early_exec_public_key = "9su8rL2Q2RTyjrsAk85JEViwKwmtMinmAdmWt1pkjhFT"
early_exec_secret_key = "<secret — leave the real line in your file>"
```

The header in the real file also says you may omit a secret to deny that
action, and you may reuse one keypair for several actions. Import stores a
copy in the wallet. Keep the TOML as the backup.

Who should hold which secret in a real DAO:

| Key | What it can do |
| --- | --- |
| Notes | Decrypt notes attached to DAO transactions. |
| Proposer | Create proposals, and only if that wallet also holds enough governance tokens. |
| Proposals | Read proposal plaintext. |
| Votes | Read the vote plaintext. |
| Exec | Run a proposal after its block window has ended and the vote passed. |
| Early exec | Run a proposal early, once the early-exec quorum and the approval ratio are met. |

For a solo test, one wallet holds all of them. For a real DAO, split them.
Someone with the proposer secret still cannot propose unless they hold
`proposer_limit` of the governance token.

Name it and view it:

```bash
drk --config drk.toml dao import GuideDAO < guide-dao.toml
drk --config drk.toml dao list
drk --config drk.toml dao list GuideDAO
```

```text
Importing "GuideDAO" DAO into the wallet
0. GuideDAO
```

`dao view` reads TOML from stdin. It does not take the name:

```bash
drk --config drk.toml dao view < guide-dao.toml
```

`dao list GuideDAO` prints the parameters, the bulla, and the DAO payment
address. Before the mint is scanned, the leaf fields are `None`. Secrets are
included; they are omitted in this excerpt.

```text
DAO Parameters
==============
Name: GuideDAO
Bulla: FzPGVLhKpUpEiZ4MLfir8BfDaEDMktW4tjAqkjE4QugE
Proposer limit: 20 (2000000000)
Quorum: 10 (1000000000)
Early Exec Quorum: 10 (1000000000)
Approval ratio: 0.67
Governance Token ID: C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U
Notes Public key: 9Shv7ND1KepownbzV2XBD3x97xNUqZXrAJ7AzL7nfTjR
Proposer Public key: 7LWaRRKJqo512mpP7tvYwrp8UtfDw6C91MBq1bq2QGyW
Proposals Public key: ApHgeWWLoXfeeuqJWnLp2wq1RyPp3MGDwHpuNqnpi9GM
Votes Public key: 6kS28P3xCzyaHoLBEUVjLkAanFxhD4WVGGaAA9zkHZqA
Exec Public key: 5ZCyk29i2HA2F7qT1PY12KCcVqp3rmyqfGvQ79UckgwS
Early Exec Public key: 9su8rL2Q2RTyjrsAk85JEViwKwmtMinmAdmWt1pkjhFT
Bulla blind: ATNM3RBasaacrf3nequr8trjDrPfUNR1NwZwqZAK8gCy
Leaf position: None
Mint height: None
Transaction hash: None
Call index: None
Wallet Address: DcGqZp2qdGpg4KhdycAK3u63PmLRJaLyZvab9B68GhpEPgsEnpjffs4F
```

## 5. Deploy the DAO

"Deploy" here means mint the DAO parameters into the DAO contract. There is no
WASM file.

```bash
drk --config drk.toml dao mint GuideDAO | drk --config drk.toml broadcast
```

```text
Transaction ID: d6b2da3102b37bcc7e545c93eb6ef728be785ef2433338b9d58c373d9af8f52f
```

Mine, scan, then `dao list GuideDAO` again. The same parameter dump now
has the leaf filled in:

```text
Leaf position: Position(0)
Mint height: 11
Transaction hash: d6b2da3102b37bcc7e545c93eb6ef728be785ef2433338b9d58c373d9af8f52f
Call index: 0
```

`Leaf position: None` means the wallet has not seen the mint yet. Scan again
before you build proposals.

The DAO's own payment address is not your wallet address:

```bash
drk --config drk.toml dao spend-hook
drk --config drk.toml dao list GuideDAO
```

Spend hook (same value on localnet, testnet, and mainnet, because it is the
DAO contract's exec function id):

```text
6iW9nywZYvyhcM7P1iLwYkh92rvYtREDsC8hgqf2GLuT
```

DAO address in this run:

```text
DcGqZp2qdGpg4KhdycAK3u63PmLRJaLyZvab9B68GhpEPgsEnpjffs4F
```

Still run `dao spend-hook` yourself. Do not skip it because a guide printed it.

## 6. Fund the treasury

Send 10 DAWN to the DAO address. The last two arguments are the spend hook and
the DAO bulla. They are what make the coin spendable by `dao exec` later.

```bash
drk --config drk.toml transfer \
  10 DAWN \
  DcGqZp2qdGpg4KhdycAK3u63PmLRJaLyZvab9B68GhpEPgsEnpjffs4F \
  6iW9nywZYvyhcM7P1iLwYkh92rvYtREDsC8hgqf2GLuT \
  FzPGVLhKpUpEiZ4MLfir8BfDaEDMktW4tjAqkjE4QugE \
  | drk --config drk.toml broadcast
```

```text
Transaction ID: 9a9ab2ca3519ab80b2c1ccdf1c986010bce72d9e6ee92a0693ff7a84141a32f4
```

Mine and scan.

```bash
drk --config drk.toml dao balance GuideDAO
```

```text
 Token ID                                     | Aliases | Balance
----------------------------------------------+---------+---------
 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S | DAWN    | 10
```

A transfer that omits the hook and the bulla can still pay the DAO address,
and those coins will not show up as treasury `dao exec` can move. Send treasury
funds with both arguments.

`transfer` spends one coin. If the wallet only has smaller coins that do not
individually cover the amount plus the fee, the command fails even when the
sum would cover it. Mint or receive a single coin that is large enough.

## 7. Propose a payout

`dao propose-transfer` writes the proposal into the wallet. It does not
broadcast. The arguments are:

```text
dao propose-transfer <DAO> <duration-in-block-windows> <amount> <token> <recipient>
```

Duration `1` means "one block window." On public testnet that is about four
hours. This proposal pays 4 DAWN back to the same wallet that funded the DAO,
which makes the balance check obvious.

```bash
drk --config drk.toml dao propose-transfer \
  GuideDAO 1 4 DAWN \
  DXqLbrzhvi8Za3umAQT1A5LyUzoJthzCHjbDYunWrszsYEfvtkchMoNs
```

```text
Generated proposal: 8tmVSXYECNs3u73K2VX5ans4nrWdq5BGFtNvv65yqnou
```

Look at it before you publish it:

```bash
drk --config drk.toml dao proposal 8tmVSXYECNs3u73K2VX5ans4nrWdq5BGFtNvv65yqnou
```

```text
Proposal parameters
===================
Bulla: 8tmVSXYECNs3u73K2VX5ans4nrWdq5BGFtNvv65yqnou
DAO Bulla: FzPGVLhKpUpEiZ4MLfir8BfDaEDMktW4tjAqkjE4QugE
Creation block window: 0
Duration: 1 (Block windows)

Invoked contracts:
        Contract: Fd8kfCuqU8BoFFp6GcXv5pC8XXRkBK7gUPQX5XDz7iXj
        Function: 4
        Data:
                Recipient: DXqLbrzhvi8Za3umAQT1A5LyUzoJthzCHjbDYunWrszsYEfvtkchMoNs
                Amount: 400000000 (4)
                Token: 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S
                Spend hook: -
                User data: -
                Blind: BqV7yeAKGHEEkyKZJPVzbTrsJbTnQkWAEQJP2G94aRKF

        Contract: BZHKGQ26bzmBithTQYTJtjo2QdCqpkR9tjSBopT4yf4o
        Function: 3
        Data: -
```

Read that as two calls inside one proposal:

- Money (`Fd8kfCuqU8BoFFp6GcXv5pC8XXRkBK7gUPQX5XDz7iXj`), function 4, sends 4 DAWN.
- DAO (`BZHKGQ26bzmBithTQYTJtjo2QdCqpkR9tjSBopT4yf4o`), function 3, is the auth
  child that proves this payout was allowed. You do not fill it in by hand.
  `propose-transfer` adds it.

Publish the proposal:

```bash
drk --config drk.toml dao proposal 8tmVSXYECNs3u73K2VX5ans4nrWdq5BGFtNvv65yqnou --mint-proposal \
  | drk --config drk.toml broadcast
```

```text
Transaction ID: af8604c240db3bca58e0bcf8b7f7349f431d5f3b9648c19d3a6cf95d3a93dc25
```

Mine and scan until the leaf is filled in. This run needed more than one block.

```text
Proposal leaf position: Position(0)
Proposal mint height: 20
Proposal transaction hash: af8604c240db3bca58e0bcf8b7f7349f431d5f3b9648c19d3a6cf95d3a93dc25
Proposal call index: 0
```

If you vote too early, `drk` prints:

```text
Failed to create DAO Vote transaction: [dao_vote] Proposal seems to not have been deployed yet
```

That is a scan lag, not a rejected proposal. Scan again and retry.

There is also `dao propose` for a generic proposal that does not move coins.
This walkthrough uses `propose-transfer` because the balance change is easy to
check.

## 8. Vote

Vote `1` is yes. Vote `0` is no. The weight defaults to all of your governance
tokens.

```bash
drk --config drk.toml dao vote 8tmVSXYECNs3u73K2VX5ans4nrWdq5BGFtNvv65yqnou 1 \
  | drk --config drk.toml broadcast
```

```text
Transaction ID: 70a5132af960f810b16cff0075bedc8f493c8c589707654c33a1f02883400cab
```

Mine and scan, then view the proposal again:

```text
Votes:
 Transaction                                                      | Tokens | Vote
------------------------------------------------------------------+--------+------
 70a5132af960f810b16cff0075bedc8f493c8c589707654c33a1f02883400cab | 40     | Yes

Total tokens votes: 40
Total tokens Yes votes: 40 (100.00%)
Total tokens No votes: 0 (0.00%)
Voting status: Ongoing
Current proposal outcome: Approved
```

40 yes tokens is above the quorum of 10, and 100% is above the 0.67 approval
ratio, so the outcome is `Approved`. `Voting status: Ongoing` is still correct:
the block window has not ended. Early execution is allowed in that state.
After the window ends, the exec key (not the early-exec key) is what runs it.

The wallet's ANON balance was still 40 after this vote was mined. Voting did
not destroy the governance tokens.

## 9. Execute early and check the money

```bash
drk --config drk.toml dao exec 8tmVSXYECNs3u73K2VX5ans4nrWdq5BGFtNvv65yqnou --early \
  | drk --config drk.toml broadcast
```

```text
[mark_tx_spend] Processing transaction: e0735dbd8a9e3b39e41f5db44223ac4995adc7482d9a783658f0207b8f785cf6
[mark_tx_spend] Found Money contract in call 1
[mark_tx_spend] Found Money contract in call 3
Broadcasting transaction...
Transaction ID: e0735dbd8a9e3b39e41f5db44223ac4995adc7482d9a783658f0207b8f785cf6
```

The first scan after the broadcast can still show `No unspent balances found`
for the DAO. That is the wallet refreshing the treasury coin. Scan again.

```bash
drk --config drk.toml dao balance GuideDAO
drk --config drk.toml wallet balance
```

DAO treasury:

```text
 Token ID                                     | Aliases | Balance
----------------------------------------------+---------+---------
 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S | DAWN    | 6
```

Wallet:

```text
 Token ID                                     | Aliases | Balance
----------------------------------------------+---------+---------
 241vANigf1Cy3ytjM1KHXiVECxgxdK4yApddL8KcLssb | DRK     | 560
 2YeDBh86LETVhJ2Jr192reLR1mkbVtwFZQGb3X8LTx6S | DAWN    | 14
 C8VjRTV1QefBsCFg42YkU4uzf8MLnHpNyPbqBvkaY76U | ANON    | 40
```

The DAWN path in this run:

| Step | Wallet DAWN | DAO DAWN |
| --- | ---: | ---: |
| After mint | 20 | 0 |
| After funding the treasury | 10 | 10 |
| After early exec of the 4 DAWN proposal | 14 | 6 |

DRK moved only because of mining rewards and fees. Match the DAWN column, not
the DRK total.

Without `--early`, wait until `Voting status` is no longer `Ongoing` and the
outcome is still `Approved`, then run `dao exec <bulla>` with the exec key.
On a fresh localnet the window index may not advance unless the chain grows
for a long time. `--early` is the practical way to finish a local test.

## Testnet, then mainnet

The DAO commands do not change. The network, the fees, and the clock do.

1. Build `darkfid` and `drk` from the same pin you trust. Moonshine's pin is
   recorded in [darkfi-pin.md](darkfi-pin.md). A random `darkfi` master checkout
   is a different chain protocol than that pin.
2. In `drk.toml` set `network = "testnet"` or `network = "mainnet"`.
   The sample `drk_config.toml` in the DarkFi tree uses
   `tcp://127.0.0.1:18345` for testnet and `tcp://127.0.0.1:8345` for mainnet.
   Point `endpoint` at a `darkfid` you run, synced to that network.
3. Use a new wallet. Do not copy `wallet.db` or `guide-dao.toml` from localnet.
   Addresses and keys are network-specific in practice because you do not want
   a test key anywhere near real funds, and localnet history is not testnet
   history.
4. Get DRK for fees before `token mint`. On testnet, mine with your node or
   use the public faucet. On mainnet, you buy or earn DRK. Nothing in this
   guide mints DRK. `token generate-mint` creates a new token, not DRK.
5. Keep `duration` honest. `1` is about four hours on public testnet, and the
   same order of magnitude on mainnet. Use a short duration only when you
   intend to sit through it, or set an early-exec quorum you are willing to meet.
6. Confirm on a block explorer you trust, and by `scan` in your own wallet.
   The testnet explorer linked from the Moonshine README is
   <https://explorer.testnet.dark.fi>. Localnet transactions will not appear there.
7. Aliases (`ANON`, `GuideDAO`) still exist only in your wallet. Publish the
   token ID and the DAO bulla, not the nickname.

Same sequence on testnet, with your own address and your own token names:

```bash
drk --config drk.toml wallet address
drk --config drk.toml token generate-mint
drk --config drk.toml alias add ANON <token-id-just-printed>
drk --config drk.toml token mint ANON 40 <your-address> | drk --config drk.toml broadcast
drk --config drk.toml scan
drk --config drk.toml dao create 20 10 10 0.67 ANON > guide-dao.toml
drk --config drk.toml dao import GuideDAO < guide-dao.toml
drk --config drk.toml dao mint GuideDAO | drk --config drk.toml broadcast
drk --config drk.toml scan
```

Then fund, propose, vote, and exec exactly as above. Wait for `scan` to show
a leaf position between mint and vote.

## Moonshine path (token, DAO mint, deploy)

Point Moonshine at a local lightwalletd that follows the same `darkfid`
(example: `server_url = "http://127.0.0.1:9068"`, `network = "localnet"`).
Fund the wallet with DRK, then:

```bash
moonshine -w localdao sync
moonshine -w localdao token generate-mint --alias ANON
moonshine -w localdao token mint ANON 100 "<your payment address>"
# mine / wait for confirmation, then:
moonshine -w localdao sync
moonshine -w localdao dao create GuideDAO 20 10 10 0.67 ANON
moonshine -w localdao dao mint GuideDAO
moonshine -w localdao dao list
moonshine -w localdao dao view GuideDAO
moonshine -w localdao dao spend-hook
moonshine -w localdao dao balance GuideDAO
moonshine -w localdao dao calls
moonshine -w localdao dao proposals

# Fund the DAO treasury with custom tokens or DRK:
# moonshine -w localdao tx send --to <DAO_TREASURY_ADDR> --amount 10 --token ANON --spend-hook $(moonshine dao spend-hook) --user-data <DAO_BULLA>

# Optional Deployooor upload (needs a wasm32 binary):
moonshine -w localdao contract generate-deploy
moonshine -w localdao contract deploy <CONTRACT_ID> ./my_contract.wasm
moonshine -w localdao contract lock <CONTRACT_ID>
```

Each mint/deploy/lock spends a small DRK fee through lightwalletd. After the
block is mined, sync again so change notes are spendable. Proposal / vote /
exec still use `drk` as in the sections above.

## Receiving the payout in Moonshine

Default Moonshine sync is padded trial decryption, so a `drk` or DAO payout to
your address is found without `--unifomr`. Use `--force-trial` only when you
need to re-scan past a stuck cursor. Experimental `--unifomr` can miss clue-less
payments.

```bash
moonshine sync
moonshine balance
moonshine tx list
```

Moonshine can mint tokens, create/mint DAOs, and deploy/lock WASM. It does not
yet propose, vote, or exec; do those steps in `drk`.

## A custom WASM contract

Skip this if your goal is a DAO. The DAO you minted above is live without it.

When you do have a compiled contract binary:

```bash
# Moonshine (broadcasts through lightwalletd)
moonshine contract generate-deploy
moonshine contract deploy <CONTRACT_ID> <WASM_FILE>
moonshine sync
moonshine contract lock <CONTRACT_ID>

# or drk against darkfid RPC
drk --config drk.toml contract generate-deploy
drk --config drk.toml contract deploy <CONTRACT_ID> <WASM_FILE> \
  | drk --config drk.toml broadcast
drk --config drk.toml scan
drk --config drk.toml contract lock <CONTRACT_ID> \
  | drk --config drk.toml broadcast
```

`contract generate-deploy` only creates a key. The chain does not have your
contract until `contract deploy` is mined. Building the WASM is a separate
project (Rust crate → `wasm32-unknown-unknown`). The DarkFi book walks through
a hello-world contract. Do not paste this DAO TOML into a WASM deploy, and do
not expect `dao mint` to upload a `.wasm` file.

## When something fails

| What you see | What it usually means |
| --- | --- |
| `Active profile 'tcp+tls' not defined in net.profiles` | `darkfid.toml` is missing the inbound profile block from step 1. |
| `wallet balance` has no DRK | Mine another block and `scan` again, or the miner is pointed at a different address. |
| `Proposal seems to not have been deployed yet` | The mint is not in the wallet index yet. `scan`, check `Proposal leaf position`, vote again. |
| `No unspent balances found` right after exec | Scan once more. The treasury coin is being refreshed. |
| Transfer says it cannot build a transaction | One coin has to cover the amount and the fee. Split coins are not combined. |
| Money `Custom(5)` while spending | The wallet's Money Merkle tree is missing older leaves. In Moonshine, `moonshine sync --force-trial --rebuild-merkle` rebuilds it. `drk scan` on a full node is the equivalent check before you retry the spend. |
| Freeze, then mint fails | That is the freeze working. |
| `dao exec` without `--early` fails while status is `Ongoing` | The window is still open. Use the early-exec key and `--early`, or wait out `duration`. |

## Command list

```text
# drk
wallet initialize | wallet address | wallet balance | scan
token generate-mint | token import | token list | token mint | token freeze
alias add | alias show
dao create | dao import | dao list | dao view | dao mint | dao spend-hook | dao balance
dao propose-transfer | dao proposal | dao proposal --mint-proposal
dao vote | dao exec | dao exec --early
broadcast
contract generate-deploy | contract deploy | contract lock

# moonshine (3.1.6+)
sync | balance | tx send | tx list
token generate-mint | token import | token list | token mint | token freeze
dao create | dao import | dao list | dao spend-hook | dao balance | dao calls | dao view | dao proposals | dao mint
contract generate-deploy | contract list | contract events | contract deploy | contract lock
```
