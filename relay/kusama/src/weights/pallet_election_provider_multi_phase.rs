// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Autogenerated weights for `pallet_election_provider_multi_phase`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-12-14, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ggwpez-ref-hw`, CPU: `Intel(R) Xeon(R) CPU @ 2.60GHz`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("../kusama-chain-spec.json")`, DB CACHE: 1024

// Executed Command:
// ./target/release/polkadot
// benchmark
// pallet
// --chain=../kusama-chain-spec.json
// --steps
// 50
// --repeat
// 20
// --pallet=pallet_election_provider_multi_phase
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --output
// ./kusama-weights/
// --header
// ./file_header.txt

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_election_provider_multi_phase`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_election_provider_multi_phase::WeightInfo for WeightInfo<T> {
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentPlannedSession` (r:1 w:0)
	/// Proof: `Staking::CurrentPlannedSession` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasStartSessionIndex` (r:1 w:0)
	/// Proof: `Staking::ErasStartSessionIndex` (`max_values`: None, `max_size`: Some(16), added: 2491, mode: `MaxEncodedLen`)
	/// Storage: `Babe::EpochIndex` (r:1 w:0)
	/// Proof: `Babe::EpochIndex` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	/// Storage: `Babe::GenesisSlot` (r:1 w:0)
	/// Proof: `Babe::GenesisSlot` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	/// Storage: `Babe::CurrentSlot` (r:1 w:0)
	/// Proof: `Babe::CurrentSlot` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ForceEra` (r:1 w:0)
	/// Proof: `Staking::ForceEra` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	fn on_initialize_nothing() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `821`
		//  Estimated: `3481`
		// Minimum execution time: 22_321_000 picoseconds.
		Weight::from_parts(22_811_000, 0)
			.saturating_add(Weight::from_parts(0, 3481))
			.saturating_add(T::DbWeight::get().reads(8))
	}
	/// Storage: `ElectionProviderMultiPhase::Round` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::Round` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	fn on_initialize_open_signed() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `80`
		//  Estimated: `1565`
		// Minimum execution time: 12_579_000 picoseconds.
		Weight::from_parts(13_255_000, 0)
			.saturating_add(Weight::from_parts(0, 1565))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ElectionProviderMultiPhase::Round` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::Round` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	fn on_initialize_open_unsigned() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `80`
		//  Estimated: `1565`
		// Minimum execution time: 13_644_000 picoseconds.
		Weight::from_parts(14_011_000, 0)
			.saturating_add(Weight::from_parts(0, 1565))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `ElectionProviderMultiPhase::QueuedSolution` (r:0 w:1)
	/// Proof: `ElectionProviderMultiPhase::QueuedSolution` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	fn finalize_signed_phase_accept_solution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `174`
		//  Estimated: `3593`
		// Minimum execution time: 33_855_000 picoseconds.
		Weight::from_parts(34_487_000, 0)
			.saturating_add(Weight::from_parts(0, 3593))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn finalize_signed_phase_reject_solution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `174`
		//  Estimated: `3593`
		// Minimum execution time: 22_846_000 picoseconds.
		Weight::from_parts(23_197_000, 0)
			.saturating_add(Weight::from_parts(0, 3593))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ElectionProviderMultiPhase::SnapshotMetadata` (r:0 w:1)
	/// Proof: `ElectionProviderMultiPhase::SnapshotMetadata` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::DesiredTargets` (r:0 w:1)
	/// Proof: `ElectionProviderMultiPhase::DesiredTargets` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::Snapshot` (r:0 w:1)
	/// Proof: `ElectionProviderMultiPhase::Snapshot` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `v` is `[1000, 2000]`.
	/// The range of component `t` is `[500, 1000]`.
	fn create_snapshot_internal(v: u32, _t: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 616_833_000 picoseconds.
		Weight::from_parts(708_554_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			// Standard Error: 6_289
			.saturating_add(Weight::from_parts(593_263, 0).saturating_mul(v.into()))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ElectionProviderMultiPhase::SignedSubmissionIndices` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::SignedSubmissionIndices` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::SignedSubmissionNextIndex` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::SignedSubmissionNextIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::SnapshotMetadata` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::SnapshotMetadata` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::SignedSubmissionsMap` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::SignedSubmissionsMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::QueuedSolution` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::QueuedSolution` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::Round` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::Round` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::DesiredTargets` (r:0 w:1)
	/// Proof: `ElectionProviderMultiPhase::DesiredTargets` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::Snapshot` (r:0 w:1)
	/// Proof: `ElectionProviderMultiPhase::Snapshot` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `a` is `[500, 800]`.
	/// The range of component `d` is `[200, 400]`.
	fn elect_queued(a: u32, d: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `831 + a * (1152 ±0) + d * (47 ±0)`
		//  Estimated: `4281 + a * (1152 ±0) + d * (48 ±0)`
		// Minimum execution time: 559_217_000 picoseconds.
		Weight::from_parts(589_361_000, 0)
			.saturating_add(Weight::from_parts(0, 4281))
			// Standard Error: 11_643
			.saturating_add(Weight::from_parts(658_553, 0).saturating_mul(a.into()))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(8))
			.saturating_add(Weight::from_parts(0, 1152).saturating_mul(a.into()))
			.saturating_add(Weight::from_parts(0, 48).saturating_mul(d.into()))
	}
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::SnapshotMetadata` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::SnapshotMetadata` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::SignedSubmissionIndices` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::SignedSubmissionIndices` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::SignedSubmissionNextIndex` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::SignedSubmissionNextIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `TransactionPayment::NextFeeMultiplier` (r:1 w:0)
	/// Proof: `TransactionPayment::NextFeeMultiplier` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `ElectionProviderMultiPhase::SignedSubmissionsMap` (r:0 w:1)
	/// Proof: `ElectionProviderMultiPhase::SignedSubmissionsMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn submit() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1169`
		//  Estimated: `2654`
		// Minimum execution time: 64_978_000 picoseconds.
		Weight::from_parts(67_031_000, 0)
			.saturating_add(Weight::from_parts(0, 2654))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::Round` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::Round` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::DesiredTargets` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::DesiredTargets` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::QueuedSolution` (r:1 w:1)
	/// Proof: `ElectionProviderMultiPhase::QueuedSolution` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::SnapshotMetadata` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::SnapshotMetadata` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::Snapshot` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::Snapshot` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::MinimumUntrustedScore` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::MinimumUntrustedScore` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `v` is `[1000, 2000]`.
	/// The range of component `t` is `[500, 1000]`.
	/// The range of component `a` is `[500, 800]`.
	/// The range of component `d` is `[200, 400]`.
	fn submit_unsigned(v: u32, t: u32, a: u32, _d: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `185 + t * (32 ±0) + v * (809 ±0)`
		//  Estimated: `1670 + t * (32 ±0) + v * (809 ±0)`
		// Minimum execution time: 9_438_158_000 picoseconds.
		Weight::from_parts(9_526_464_000, 0)
			.saturating_add(Weight::from_parts(0, 1670))
			// Standard Error: 41_319
			.saturating_add(Weight::from_parts(207_506, 0).saturating_mul(v.into()))
			// Standard Error: 122_446
			.saturating_add(Weight::from_parts(10_261_261, 0).saturating_mul(a.into()))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(t.into()))
			.saturating_add(Weight::from_parts(0, 809).saturating_mul(v.into()))
	}
	/// Storage: `ElectionProviderMultiPhase::DesiredTargets` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::DesiredTargets` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::Snapshot` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::Snapshot` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::Round` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::Round` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ElectionProviderMultiPhase::MinimumUntrustedScore` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::MinimumUntrustedScore` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `v` is `[1000, 2000]`.
	/// The range of component `t` is `[500, 1000]`.
	/// The range of component `a` is `[500, 800]`.
	/// The range of component `d` is `[200, 400]`.
	fn feasibility_check(v: u32, t: u32, a: u32, _d: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `160 + t * (32 ±0) + v * (809 ±0)`
		//  Estimated: `1645 + t * (32 ±0) + v * (809 ±0)`
		// Minimum execution time: 8_109_407_000 picoseconds.
		Weight::from_parts(8_353_454_000, 0)
			.saturating_add(Weight::from_parts(0, 1645))
			// Standard Error: 29_585
			.saturating_add(Weight::from_parts(364_975, 0).saturating_mul(v.into()))
			// Standard Error: 87_672
			.saturating_add(Weight::from_parts(6_965_740, 0).saturating_mul(a.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(t.into()))
			.saturating_add(Weight::from_parts(0, 809).saturating_mul(v.into()))
	}
}
