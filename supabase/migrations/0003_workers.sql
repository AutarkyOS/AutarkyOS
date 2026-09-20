-- Worker names, and which address a name's shares are owed to.
--
-- The pool logs shares against whatever string a rig sent in
-- `mining.authorize`. `tools/distribute.py` turns that log into a Merkle tree
-- of `(address, amount)` leaves, and a name that is not already an address has
-- to become one somewhere. This table is that somewhere.
--
-- ### Why this is not gated on a balance, where `link` is
--
-- `link` refuses a wallet under the threshold because what it hands out is
-- access to builds. This hands out nothing: it records who a name's work
-- belongs to. Gating it would mean a person had to buy before they could mine,
-- which inverts the order the whole design depends on -- you mine, you accrue,
-- and the gate is checked by the contract at claim time against a balance held
-- *then*. A miner who never buys simply never claims, and their allocation
-- returns to the operator through `reclaim`.
--
-- ### What a compromise of this table buys an attacker
--
-- Misattribution of future shares, and nothing else. It cannot mint a claim:
-- the contract re-reads the gate itself, and the root is published from a
-- ledger the pool keeps independently. That division is deliberate and is the
-- same one `supabase/README.md` draws about the update channel.

create table if not exists workers (
  -- The name exactly as the rig sends it, because that is the string
  -- `distribute.py` looks up. Storing a normalised form and serving that would
  -- silently fail to match a ledger row spelled differently.
  worker      text primary key,

  -- Case-folded, and unique. Two people holding `Alice` and `alice` is not a
  -- collision the pool would notice and is exactly the shape a name-lookalike
  -- attack takes. Uniqueness is enforced here rather than in the function so a
  -- race between two requests cannot produce two rows.
  worker_fold text        not null,

  address     text        not null,
  claimed_at  timestamptz not null default now(),

  -- When the address last moved. Read by the distributor, not by people: an
  -- epoch whose mapping changed while it was accruing would pay the new owner
  -- for the old owner's work, so a distribution refuses entries newer than the
  -- epoch it is paying unless told otherwise.
  updated_at  timestamptz not null default now()
);

create unique index if not exists workers_fold on workers (worker_fold);
create index if not exists workers_address on workers (address);

alter table workers enable row level security;
