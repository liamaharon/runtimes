// Copyright (C) Parity Technologies and the various Polkadot contributors, see Contributions.md
// for a list of specific contributors.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Autogenerated weights for `runtime_parachains::disputes::slashing`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 32.0.0
//! DATE: 2024-03-10, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ggwpez-ref-hw`, CPU: `Intel(R) Xeon(R) CPU @ 2.60GHz`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("./polkadot-chain-spec.json")`, DB CACHE: 1024

// Executed Command:
// ./target/production/polkadot
// benchmark
// pallet
// --chain=./polkadot-chain-spec.json
// --steps=50
// --repeat=20
// --pallet=runtime_parachains::disputes::slashing
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./polkadot-weights/
// --header=./file_header.txt

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `runtime_parachains::disputes::slashing`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> runtime_parachains::disputes::slashing::WeightInfo for WeightInfo<T> {
	/// Storage: `Session::CurrentIndex` (r:1 w:0)
	/// Proof: `Session::CurrentIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Historical::HistoricalSessions` (r:1 w:0)
	/// Proof: `Historical::HistoricalSessions` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `ParasSlashing::UnappliedSlashes` (r:1 w:1)
	/// Proof: `ParasSlashing::UnappliedSlashes` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Offences::ConcurrentReportsIndex` (r:1 w:1)
	/// Proof: `Offences::ConcurrentReportsIndex` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Offences::Reports` (r:1 w:1)
	/// Proof: `Offences::Reports` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::SlashRewardFraction` (r:1 w:0)
	/// Proof: `Staking::SlashRewardFraction` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ActiveEra` (r:1 w:0)
	/// Proof: `Staking::ActiveEra` (`max_values`: Some(1), `max_size`: Some(13), added: 508, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasStartSessionIndex` (r:1 w:0)
	/// Proof: `Staking::ErasStartSessionIndex` (`max_values`: None, `max_size`: Some(16), added: 2491, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Invulnerables` (r:1 w:0)
	/// Proof: `Staking::Invulnerables` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::ValidatorSlashInEra` (r:1 w:1)
	/// Proof: `Staking::ValidatorSlashInEra` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SlashingSpans` (r:1 w:1)
	/// Proof: `Staking::SlashingSpans` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::SpanSlash` (r:1 w:1)
	/// Proof: `Staking::SpanSlash` (`max_values`: None, `max_size`: Some(76), added: 2551, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:1)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForValidators` (r:1 w:1)
	/// Proof: `Staking::CounterForValidators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:3 w:3)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(558), added: 3033, mode: `MaxEncodedLen`)
	/// Storage: `Staking::OffendingValidators` (r:1 w:1)
	/// Proof: `Staking::OffendingValidators` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Session::Validators` (r:1 w:0)
	/// Proof: `Session::Validators` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Session::DisabledValidators` (r:1 w:1)
	/// Proof: `Session::DisabledValidators` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `System::Digest` (r:1 w:1)
	/// Proof: `System::Digest` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::UnappliedSlashes` (r:1 w:1)
	/// Proof: `Staking::UnappliedSlashes` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::ForceEra` (r:1 w:1)
	/// Proof: `Staking::ForceEra` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[4, 1000]`.
	fn report_dispute_lost(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `5578 + n * (220 ±0)`
		//  Estimated: `8877 + n * (350 ±0)`
		// Minimum execution time: 78_696_000 picoseconds.
		Weight::from_parts(158_454_472, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			// Standard Error: 2_479
			.saturating_add(Weight::from_parts(187_148, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(23))
			.saturating_add(T::DbWeight::get().writes(15))
			.saturating_add(Weight::from_parts(0, 350).saturating_mul(n.into()))
	}
}
