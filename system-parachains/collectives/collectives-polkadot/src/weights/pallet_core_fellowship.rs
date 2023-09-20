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

//! Autogenerated weights for `pallet_core_fellowship`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-09-20, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `a3dce7bd4066`, CPU: `Intel(R) Xeon(R) CPU @ 2.60GHz`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("spec-collectives-polkadot.json")`, DB CACHE: 1024

// Executed Command:
// /builds/polkadot-sdk/target/production/polkadot-parachain
// benchmark
// pallet
// --chain=spec-collectives-polkadot.json
// --pallet=pallet_core_fellowship
// --extrinsic=
// --output=/builds/runtimes/system-parachains/collectives/collectives-polkadot/src/weights
// --header=/builds/bench/header.txt
// --no-median-slopes
// --no-min-squares

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_core_fellowship`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_core_fellowship::WeightInfo for WeightInfo<T> {
	/// Storage: `FellowshipCore::Params` (r:0 w:1)
	/// Proof: `FellowshipCore::Params` (`max_values`: Some(1), `max_size`: Some(364), added: 859, mode: `MaxEncodedLen`)
	fn set_params() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 7_486_000 picoseconds.
		Weight::from_parts(7_917_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::Members` (r:1 w:1)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::Params` (r:1 w:0)
	/// Proof: `FellowshipCore::Params` (`max_values`: Some(1), `max_size`: Some(364), added: 859, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::MemberCount` (r:1 w:1)
	/// Proof: `FellowshipCollective::MemberCount` (`max_values`: None, `max_size`: Some(14), added: 2489, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::IdToIndex` (r:1 w:0)
	/// Proof: `FellowshipCollective::IdToIndex` (`max_values`: None, `max_size`: Some(54), added: 2529, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::MemberEvidence` (r:1 w:1)
	/// Proof: `FellowshipCore::MemberEvidence` (`max_values`: None, `max_size`: Some(65581), added: 68056, mode: `MaxEncodedLen`)
	fn bump_offboard() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `66111`
		//  Estimated: `69046`
		// Minimum execution time: 120_644_000 picoseconds.
		Weight::from_parts(122_570_000, 0)
			.saturating_add(Weight::from_parts(0, 69046))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::Members` (r:1 w:1)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::Params` (r:1 w:0)
	/// Proof: `FellowshipCore::Params` (`max_values`: Some(1), `max_size`: Some(364), added: 859, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::MemberCount` (r:1 w:1)
	/// Proof: `FellowshipCollective::MemberCount` (`max_values`: None, `max_size`: Some(14), added: 2489, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::IdToIndex` (r:1 w:0)
	/// Proof: `FellowshipCollective::IdToIndex` (`max_values`: None, `max_size`: Some(54), added: 2529, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::MemberEvidence` (r:1 w:1)
	/// Proof: `FellowshipCore::MemberEvidence` (`max_values`: None, `max_size`: Some(65581), added: 68056, mode: `MaxEncodedLen`)
	fn bump_demote() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `66221`
		//  Estimated: `69046`
		// Minimum execution time: 125_224_000 picoseconds.
		Weight::from_parts(126_976_000, 0)
			.saturating_add(Weight::from_parts(0, 69046))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `FellowshipCollective::Members` (r:1 w:0)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	fn set_active() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `460`
		//  Estimated: `3514`
		// Minimum execution time: 17_517_000 picoseconds.
		Weight::from_parts(17_917_000, 0)
			.saturating_add(Weight::from_parts(0, 3514))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::Members` (r:1 w:1)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::MemberCount` (r:1 w:1)
	/// Proof: `FellowshipCollective::MemberCount` (`max_values`: None, `max_size`: Some(14), added: 2489, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::IndexToId` (r:0 w:1)
	/// Proof: `FellowshipCollective::IndexToId` (`max_values`: None, `max_size`: Some(54), added: 2529, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::IdToIndex` (r:0 w:1)
	/// Proof: `FellowshipCollective::IdToIndex` (`max_values`: None, `max_size`: Some(54), added: 2529, mode: `MaxEncodedLen`)
	fn induct() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `218`
		//  Estimated: `3514`
		// Minimum execution time: 26_866_000 picoseconds.
		Weight::from_parts(27_552_000, 0)
			.saturating_add(Weight::from_parts(0, 3514))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	/// Storage: `FellowshipCollective::Members` (r:1 w:1)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::Params` (r:1 w:0)
	/// Proof: `FellowshipCore::Params` (`max_values`: Some(1), `max_size`: Some(364), added: 859, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::MemberCount` (r:1 w:1)
	/// Proof: `FellowshipCollective::MemberCount` (`max_values`: None, `max_size`: Some(14), added: 2489, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::MemberEvidence` (r:1 w:1)
	/// Proof: `FellowshipCore::MemberEvidence` (`max_values`: None, `max_size`: Some(65581), added: 68056, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::IndexToId` (r:0 w:1)
	/// Proof: `FellowshipCollective::IndexToId` (`max_values`: None, `max_size`: Some(54), added: 2529, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::IdToIndex` (r:0 w:1)
	/// Proof: `FellowshipCollective::IdToIndex` (`max_values`: None, `max_size`: Some(54), added: 2529, mode: `MaxEncodedLen`)
	fn promote() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `66089`
		//  Estimated: `69046`
		// Minimum execution time: 121_394_000 picoseconds.
		Weight::from_parts(122_817_000, 0)
			.saturating_add(Weight::from_parts(0, 69046))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(6))
	}
	/// Storage: `FellowshipCollective::Members` (r:1 w:0)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::MemberEvidence` (r:0 w:1)
	/// Proof: `FellowshipCore::MemberEvidence` (`max_values`: None, `max_size`: Some(65581), added: 68056, mode: `MaxEncodedLen`)
	fn offboard() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `431`
		//  Estimated: `3514`
		// Minimum execution time: 18_570_000 picoseconds.
		Weight::from_parts(19_518_000, 0)
			.saturating_add(Weight::from_parts(0, 3514))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCollective::Members` (r:1 w:0)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	fn import() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `385`
		//  Estimated: `3514`
		// Minimum execution time: 16_872_000 picoseconds.
		Weight::from_parts(17_339_000, 0)
			.saturating_add(Weight::from_parts(0, 3514))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `FellowshipCollective::Members` (r:1 w:0)
	/// Proof: `FellowshipCollective::Members` (`max_values`: None, `max_size`: Some(42), added: 2517, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::Member` (r:1 w:1)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::MemberEvidence` (r:1 w:1)
	/// Proof: `FellowshipCore::MemberEvidence` (`max_values`: None, `max_size`: Some(65581), added: 68056, mode: `MaxEncodedLen`)
	fn approve() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `66067`
		//  Estimated: `69046`
		// Minimum execution time: 107_503_000 picoseconds.
		Weight::from_parts(108_944_000, 0)
			.saturating_add(Weight::from_parts(0, 69046))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `FellowshipCore::Member` (r:1 w:0)
	/// Proof: `FellowshipCore::Member` (`max_values`: None, `max_size`: Some(49), added: 2524, mode: `MaxEncodedLen`)
	/// Storage: `FellowshipCore::MemberEvidence` (r:1 w:1)
	/// Proof: `FellowshipCore::MemberEvidence` (`max_values`: None, `max_size`: Some(65581), added: 68056, mode: `MaxEncodedLen`)
	fn submit_evidence() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `151`
		//  Estimated: `69046`
		// Minimum execution time: 92_193_000 picoseconds.
		Weight::from_parts(94_325_000, 0)
			.saturating_add(Weight::from_parts(0, 69046))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
