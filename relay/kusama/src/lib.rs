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
// along with Polkadot. If not, see <http://www.gnu.org/licenses/>.

//! The Kusama runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit.
#![recursion_limit = "512"]

use pallet_nis::WithMaximumOf;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use primitives::{
	slashing, AccountId, AccountIndex, Balance, BlockNumber, CandidateEvent, CandidateHash,
	CommittedCandidateReceipt, CoreState, DisputeState, ExecutorParams, GroupRotationInfo, Hash,
	Id as ParaId, InboundDownwardMessage, InboundHrmpMessage, Moment, Nonce,
	OccupiedCoreAssumption, PersistedValidationData, ScrapedOnChainVotes, SessionInfo, Signature,
	ValidationCode, ValidationCodeHash, ValidatorId, ValidatorIndex, LOWEST_PUBLIC_ID,
	PARACHAIN_KEY_TYPE_ID,
};
use runtime_common::{
	auctions, claims, crowdloan, impl_runtime_weights,
	impls::{
		DealWithFees, LocatableAssetConverter, VersionedLocatableAsset,
		VersionedMultiLocationConverter,
	},
	paras_registrar, prod_or_fast, slots, BalanceToU256, BlockHashCount, BlockLength,
	CurrencyToVote, SlowAdjustingFeeUpdate, U256ToBalance,
};
use scale_info::TypeInfo;
use sp_std::{cmp::Ordering, collections::btree_map::BTreeMap, prelude::*};

use runtime_parachains::{
	assigner_parachains as parachains_assigner_parachains,
	configuration as parachains_configuration, disputes as parachains_disputes,
	disputes::slashing as parachains_slashing,
	dmp as parachains_dmp, hrmp as parachains_hrmp, inclusion as parachains_inclusion,
	inclusion::{AggregateMessageOrigin, UmpQueueId},
	initializer as parachains_initializer, origin as parachains_origin, paras as parachains_paras,
	paras_inherent as parachains_paras_inherent, reward_points as parachains_reward_points,
	runtime_api_impl::v7 as parachains_runtime_api_impl,
	scheduler as parachains_scheduler, session_info as parachains_session_info,
	shared as parachains_shared,
};

use authority_discovery_primitives::AuthorityId as AuthorityDiscoveryId;
use beefy_primitives::{
	ecdsa_crypto::{AuthorityId as BeefyId, Signature as BeefySignature},
	mmr::{BeefyDataProvider, MmrLeafVersion},
};
use frame_election_provider_support::{
	bounds::ElectionBoundsBuilder, generate_solution_type, onchain, NposSolution,
	SequentialPhragmen,
};
use frame_support::{
	construct_runtime,
	genesis_builder_helper::{build_config, create_default_config},
	parameter_types,
	traits::{
		fungible::HoldConsideration, ConstU32, Contains, EitherOf, EitherOfDiverse, InstanceFilter,
		KeyOwnerProofSystem, LinearStoragePrice, PrivilegeCmp, ProcessMessage, ProcessMessageError,
		StorageMapShim, WithdrawReasons,
	},
	weights::{ConstantMultiplier, WeightMeter},
	PalletId,
};
use frame_system::EnsureRoot;
use pallet_grandpa::{fg_primitives, AuthorityId as GrandpaId};
use pallet_identity::legacy::IdentityInfo;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use pallet_session::historical as session_historical;
use pallet_transaction_payment::{CurrencyAdapter, FeeDetails, RuntimeDispatchInfo};
use sp_core::{ConstU128, OpaqueMetadata, H256};
use sp_runtime::{
	create_runtime_str, generic, impl_opaque_keys,
	traits::{
		AccountIdLookup, BlakeTwo256, Block as BlockT, ConvertInto, Extrinsic as ExtrinsicT,
		IdentityLookup, Keccak256, OpaqueKeys, SaturatedConversion, Verify,
	},
	transaction_validity::{TransactionPriority, TransactionSource, TransactionValidity},
	ApplyExtrinsicResult, FixedU128, KeyTypeId, Perbill, Percent, Permill, RuntimeDebug,
};
use sp_staking::SessionIndex;
#[cfg(any(feature = "std", test))]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use xcm::{
	latest::{InteriorMultiLocation, Junction, Junction::PalletInstance},
	VersionedMultiLocation,
};
use xcm_builder::PayOverXcm;

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_election_provider_multi_phase::{Call as EPMCall, GeometricDepositBase};
#[cfg(feature = "std")]
pub use pallet_staking::StakerStatus;
use pallet_staking::UseValidatorsMap;
use sp_runtime::traits::Get;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

/// Constant values used within the runtime.
use kusama_runtime_constants::{currency::*, fee::*, time::*, TREASURY_PALLET_ID};

// Weights used in the runtime.
mod weights;

// Voter bag threshold definitions.
mod bag_thresholds;

// Historical information of society finances.
mod past_payouts;

// XCM configurations.
pub mod xcm_config;

// Governance configurations.
pub mod governance;
use governance::{
	pallet_custom_origins, AuctionAdmin, Fellows, GeneralAdmin, LeaseAdmin, StakingAdmin,
	Treasurer, TreasurySpender,
};

#[cfg(test)]
mod tests;

impl_runtime_weights!(kusama_runtime_constants);

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Runtime version (Kusama).
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("kusama"),
	impl_name: create_runtime_str!("parity-kusama"),
	authoring_version: 2,
	spec_version: 1_001_000,
	impl_version: 0,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 25,
	state_version: 1,
};

/// The BABE epoch configuration at genesis.
pub const BABE_GENESIS_EPOCH_CONFIG: babe_primitives::BabeEpochConfiguration =
	babe_primitives::BabeEpochConfiguration {
		c: PRIMARY_PROBABILITY,
		allowed_slots: babe_primitives::AllowedSlots::PrimaryAndSecondaryVRFSlots,
	};

/// Native version.
#[cfg(any(feature = "std", test))]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

/// We currently allow all calls.
pub struct BaseFilter;
impl Contains<RuntimeCall> for BaseFilter {
	fn contains(_c: &RuntimeCall) -> bool {
		true
	}
}

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub const SS58Prefix: u8 = 2;
}

impl frame_system::Config for Runtime {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = BlockWeights;
	type BlockLength = BlockLength;
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = Nonce;
	type Hash = Hash;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = AccountIdLookup<AccountId, ()>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type DbWeight = RocksDbWeight;
	type Version = Version;
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<Balance>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = weights::frame_system::WeightInfo<Runtime>;
	type SS58Prefix = SS58Prefix;
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) * BlockWeights::get().max_block;
	pub const MaxScheduledPerBlock: u32 = 50;
	pub const NoPreimagePostponement: Option<u32> = Some(10);
}

/// Used the compare the privilege of an origin inside the scheduler.
pub struct OriginPrivilegeCmp;

impl PrivilegeCmp<OriginCaller> for OriginPrivilegeCmp {
	fn cmp_privilege(left: &OriginCaller, right: &OriginCaller) -> Option<Ordering> {
		if left == right {
			return Some(Ordering::Equal)
		}

		match (left, right) {
			// Root is greater than anything.
			(OriginCaller::system(frame_system::RawOrigin::Root), _) => Some(Ordering::Greater),
			// For every other origin we don't care, as they are not used for `ScheduleOrigin`.
			_ => None,
		}
	}
}

impl pallet_scheduler::Config for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeEvent = RuntimeEvent;
	type PalletsOrigin = OriginCaller;
	type RuntimeCall = RuntimeCall;
	type MaximumWeight = MaximumSchedulerWeight;
	// The goal of having ScheduleOrigin include AuctionAdmin is to allow the auctions track of
	// OpenGov to schedule periodic auctions.
	// Also allow Treasurer to schedule recurring payments.
	type ScheduleOrigin = EitherOf<EitherOf<EnsureRoot<AccountId>, AuctionAdmin>, Treasurer>;
	type MaxScheduledPerBlock = MaxScheduledPerBlock;
	type WeightInfo = weights::pallet_scheduler::WeightInfo<Runtime>;
	type OriginPrivilegeCmp = OriginPrivilegeCmp;
	type Preimages = Preimage;
}

parameter_types! {
	pub const PreimageBaseDeposit: Balance = deposit(2, 64);
	pub const PreimageByteDeposit: Balance = deposit(0, 1);
	pub const PreimageHoldReason: RuntimeHoldReason =
		RuntimeHoldReason::Preimage(pallet_preimage::HoldReason::Preimage);
}

impl pallet_preimage::Config for Runtime {
	type WeightInfo = weights::pallet_preimage::WeightInfo<Runtime>;
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type ManagerOrigin = EnsureRoot<AccountId>;
	type Consideration = HoldConsideration<
		AccountId,
		Balances,
		PreimageHoldReason,
		LinearStoragePrice<PreimageBaseDeposit, PreimageByteDeposit, Balance>,
	>;
}

parameter_types! {
	pub EpochDuration: u64 = prod_or_fast!(
		EPOCH_DURATION_IN_SLOTS as u64,
		2 * MINUTES as u64,
		"KSM_EPOCH_DURATION"
	);
	pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
	pub ReportLongevity: u64 =
		BondingDuration::get() as u64 * SessionsPerEra::get() as u64 * EpochDuration::get();
}

impl pallet_babe::Config for Runtime {
	type EpochDuration = EpochDuration;
	type ExpectedBlockTime = ExpectedBlockTime;

	// session module is the trigger
	type EpochChangeTrigger = pallet_babe::ExternalTrigger;

	type DisabledValidators = Session;

	type KeyOwnerProof =
		<Historical as KeyOwnerProofSystem<(KeyTypeId, pallet_babe::AuthorityId)>>::Proof;

	type EquivocationReportSystem =
		pallet_babe::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;

	type WeightInfo = ();

	type MaxAuthorities = MaxAuthorities;
	type MaxNominators = MaxNominators;
}

parameter_types! {
	pub const IndexDeposit: Balance = 100 * CENTS;
}

impl pallet_indices::Config for Runtime {
	type AccountIndex = AccountIndex;
	type Currency = Balances;
	type Deposit = IndexDeposit;
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::pallet_indices::WeightInfo<Runtime>;
}

parameter_types! {
	pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
	pub const MaxLocks: u32 = 50;
	pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
	type Balance = Balance;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type MaxLocks = MaxLocks;
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = [u8; 8];
	type WeightInfo = weights::pallet_balances_native::WeightInfo<Runtime>;
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxFreezes = ConstU32<8>;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type MaxHolds = ConstU32<2>;
}

parameter_types! {
	pub BeefySetIdSessionEntries: u32 = BondingDuration::get() * SessionsPerEra::get();
}

impl pallet_beefy::Config for Runtime {
	type BeefyId = BeefyId;
	type MaxAuthorities = MaxAuthorities;
	type MaxNominators = MaxNominators;
	type MaxSetIdSessionEntries = BeefySetIdSessionEntries;
	type OnNewValidatorSet = BeefyMmrLeaf;
	type WeightInfo = ();
	type KeyOwnerProof = <Historical as KeyOwnerProofSystem<(KeyTypeId, BeefyId)>>::Proof;
	type EquivocationReportSystem =
		pallet_beefy::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;
}

impl pallet_mmr::Config for Runtime {
	const INDEXING_PREFIX: &'static [u8] = mmr::INDEXING_PREFIX;
	type Hashing = Keccak256;
	type OnNewRoot = pallet_beefy_mmr::DepositBeefyDigest<Runtime>;
	type WeightInfo = ();
	type LeafData = pallet_beefy_mmr::Pallet<Runtime>;
}

/// MMR helper types.
mod mmr {
	use super::Runtime;
	pub use pallet_mmr::primitives::*;

	pub type Leaf = <<Runtime as pallet_mmr::Config>::LeafData as LeafDataProvider>::LeafData;
	pub type Hashing = <Runtime as pallet_mmr::Config>::Hashing;
	pub type Hash = <Hashing as sp_runtime::traits::Hash>::Output;
}

parameter_types! {
	/// Version of the produced MMR leaf.
	///
	/// The version consists of two parts;
	/// - `major` (3 bits)
	/// - `minor` (5 bits)
	///
	/// `major` should be updated only if decoding the previous MMR Leaf format from the payload
	/// is not possible (i.e. backward incompatible change).
	/// `minor` should be updated if fields are added to the previous MMR Leaf, which given SCALE
	/// encoding does not prevent old leafs from being decoded.
	///
	/// Hence we expect `major` to be changed really rarely (think never).
	/// See [`MmrLeafVersion`] type documentation for more details.
	pub LeafVersion: MmrLeafVersion = MmrLeafVersion::new(0, 0);
}

/// A BEEFY data provider that merkelizes all the parachain heads at the current block
/// (sorted by their parachain id).
pub struct ParaHeadsRootProvider;
impl BeefyDataProvider<H256> for ParaHeadsRootProvider {
	fn extra_data() -> H256 {
		let mut para_heads: Vec<(u32, Vec<u8>)> = Paras::parachains()
			.into_iter()
			.filter_map(|id| Paras::para_head(&id).map(|head| (id.into(), head.0)))
			.collect();
		para_heads.sort_by_key(|k| k.0);
		binary_merkle_tree::merkle_root::<mmr::Hashing, _>(
			para_heads.into_iter().map(|pair| pair.encode()),
		)
		.into()
	}
}

impl pallet_beefy_mmr::Config for Runtime {
	type LeafVersion = LeafVersion;
	type BeefyAuthorityToMerkleLeaf = pallet_beefy_mmr::BeefyEcdsaToEthereum;
	type LeafExtra = H256;
	type BeefyDataProvider = ParaHeadsRootProvider;
}

parameter_types! {
	pub const TransactionByteFee: Balance = 10 * MILLICENTS;
	/// This value increases the priority of `Operational` transactions by adding
	/// a "virtual tip" that's equal to the `OperationalFeeMultiplier * final_fee`.
	pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = CurrencyAdapter<Balances, DealWithFees<Self>>;
	type OperationalFeeMultiplier = OperationalFeeMultiplier;
	type WeightToFee = WeightToFee;
	type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
	type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Self>;
}

parameter_types! {
	pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}
impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = Babe;
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = weights::pallet_timestamp::WeightInfo<Runtime>;
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Babe>;
	type EventHandler = (Staking, ImOnline);
}

impl_opaque_keys! {
	pub struct SessionKeys {
		pub grandpa: Grandpa,
		pub babe: Babe,
		pub im_online: ImOnline,
		pub para_validator: Initializer,
		pub para_assignment: ParaSessionInfo,
		pub authority_discovery: AuthorityDiscovery,
		pub beefy: Beefy,
	}
}

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = AccountId;
	type ValidatorIdOf = pallet_staking::StashOf<Self>;
	type ShouldEndSession = Babe;
	type NextSessionRotation = Babe;
	type SessionManager = pallet_session::historical::NoteHistoricalRoot<Self, Staking>;
	type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type WeightInfo = weights::pallet_session::WeightInfo<Runtime>;
}

impl pallet_session::historical::Config for Runtime {
	type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
	type FullIdentificationOf = pallet_staking::ExposureOf<Runtime>;
}

parameter_types! {
	// phase durations. 1/4 of the last session for each.
	// in testing: 1min or half of the session for each
	pub SignedPhase: u32 = prod_or_fast!(
		EPOCH_DURATION_IN_SLOTS / 4,
		(1 * MINUTES).min(EpochDuration::get().saturated_into::<u32>() / 2),
		"KSM_SIGNED_PHASE"
	);
	pub UnsignedPhase: u32 = prod_or_fast!(
		EPOCH_DURATION_IN_SLOTS / 4,
		(1 * MINUTES).min(EpochDuration::get().saturated_into::<u32>() / 2),
		"KSM_UNSIGNED_PHASE"
	);

	// signed config
	pub const SignedMaxSubmissions: u32 = 16;
	pub const SignedMaxRefunds: u32 = 16 / 4;
	pub const SignedFixedDeposit: Balance = deposit(2, 0);
	pub const SignedDepositIncreaseFactor: Percent = Percent::from_percent(10);
	pub const SignedDepositByte: Balance = deposit(0, 10) / 1024;
	// Each good submission will get 1/10 KSM as reward
	pub SignedRewardBase: Balance =  UNITS / 10;
	pub BetterUnsignedThreshold: Perbill = Perbill::from_rational(5u32, 10_000);

	// 1 hour session, 15 minutes unsigned phase, 8 offchain executions.
	pub OffchainRepeat: BlockNumber = UnsignedPhase::get() / 8;

	pub const MaxElectingVoters: u32 = 12_500;
	/// We take the top 12500 nominators as electing voters and all of the validators as electable
	/// targets. Whilst this is the case, we cannot and shall not increase the size of the
	/// validator intentions.
	pub ElectionBounds: frame_election_provider_support::bounds::ElectionBounds =
		ElectionBoundsBuilder::default().voters_count(MaxElectingVoters::get().into()).build();
	pub NposSolutionPriority: TransactionPriority =
		Perbill::from_percent(90) * TransactionPriority::max_value();
	/// Setup election pallet to support maximum winners upto 2000. This will mean Staking Pallet
	/// cannot have active validators higher than this count.
	pub const MaxActiveValidators: u32 = 2000;
}

generate_solution_type!(
	#[compact]
	pub struct NposCompactSolution24::<
		VoterIndex = u32,
		TargetIndex = u16,
		Accuracy = sp_runtime::PerU16,
		MaxVoters = MaxElectingVoters,
	>(24)
);

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
	type System = Runtime;
	type Solver = SequentialPhragmen<AccountId, runtime_common::elections::OnChainAccuracy>;
	type DataProvider = Staking;
	type WeightInfo = weights::frame_election_provider_support::WeightInfo<Runtime>;
	type MaxWinners = MaxActiveValidators;
	type Bounds = ElectionBounds;
}

impl pallet_election_provider_multi_phase::MinerConfig for Runtime {
	type AccountId = AccountId;
	type MaxLength = OffchainSolutionLengthLimit;
	type MaxWeight = OffchainSolutionWeightLimit;
	type Solution = NposCompactSolution24;
	type MaxVotesPerVoter = <
		<Self as pallet_election_provider_multi_phase::Config>::DataProvider
		as
		frame_election_provider_support::ElectionDataProvider
	>::MaxVotesPerVoter;
	type MaxWinners = MaxActiveValidators;

	// The unsigned submissions have to respect the weight of the submit_unsigned call, thus their
	// weight estimate function is wired to this call's weight.
	fn solution_weight(v: u32, t: u32, a: u32, d: u32) -> Weight {
		<
			<Self as pallet_election_provider_multi_phase::Config>::WeightInfo
			as
			pallet_election_provider_multi_phase::WeightInfo
		>::submit_unsigned(v, t, a, d)
	}
}

impl pallet_election_provider_multi_phase::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type EstimateCallFee = TransactionPayment;
	type UnsignedPhase = UnsignedPhase;
	type SignedMaxSubmissions = SignedMaxSubmissions;
	type SignedMaxRefunds = SignedMaxRefunds;
	type SignedRewardBase = SignedRewardBase;
	type SignedDepositBase =
		GeometricDepositBase<Balance, SignedFixedDeposit, SignedDepositIncreaseFactor>;
	type SignedDepositByte = SignedDepositByte;
	type SignedDepositWeight = ();
	type SignedMaxWeight =
		<Self::MinerConfig as pallet_election_provider_multi_phase::MinerConfig>::MaxWeight;
	type MinerConfig = Self;
	type SlashHandler = (); // burn slashes
	type RewardHandler = (); // nothing to do upon rewards
	type SignedPhase = SignedPhase;
	type BetterUnsignedThreshold = BetterUnsignedThreshold;
	type BetterSignedThreshold = ();
	type OffchainRepeat = OffchainRepeat;
	type MinerTxPriority = NposSolutionPriority;
	type DataProvider = Staking;
	#[cfg(any(feature = "fast-runtime", feature = "runtime-benchmarks"))]
	type Fallback = onchain::OnChainExecution<OnChainSeqPhragmen>;
	#[cfg(not(any(feature = "fast-runtime", feature = "runtime-benchmarks")))]
	type Fallback = frame_election_provider_support::NoElection<(
		AccountId,
		BlockNumber,
		Staking,
		MaxActiveValidators,
	)>;
	type GovernanceFallback = onchain::OnChainExecution<OnChainSeqPhragmen>;
	type Solver = SequentialPhragmen<
		AccountId,
		pallet_election_provider_multi_phase::SolutionAccuracyOf<Self>,
		(),
	>;
	type BenchmarkingConfig = runtime_common::elections::BenchmarkConfig;
	type ForceOrigin = EitherOf<EnsureRoot<Self::AccountId>, StakingAdmin>;
	type WeightInfo = weights::pallet_election_provider_multi_phase::WeightInfo<Self>;
	type MaxWinners = MaxActiveValidators;
	type ElectionBounds = ElectionBounds;
}

parameter_types! {
	pub const BagThresholds: &'static [u64] = &bag_thresholds::THRESHOLDS;
}

type VoterBagsListInstance = pallet_bags_list::Instance1;
impl pallet_bags_list::Config<VoterBagsListInstance> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ScoreProvider = Staking;
	type WeightInfo = weights::pallet_bags_list::WeightInfo<Runtime>;
	type BagThresholds = BagThresholds;
	type Score = sp_npos_elections::VoteWeight;
}

pub struct EraPayout;
impl pallet_staking::EraPayout<Balance> for EraPayout {
	fn era_payout(
		total_staked: Balance,
		_total_issuance: Balance,
		era_duration_millis: u64,
	) -> (Balance, Balance) {
		// all para-ids that are currently active.
		let auctioned_slots = Paras::parachains()
			.into_iter()
			// all active para-ids that do not belong to a system chain is the number
			// of parachains that we should take into account for inflation.
			.filter(|i| *i >= LOWEST_PUBLIC_ID)
			.count() as u64;

		const MAX_ANNUAL_INFLATION: Perquintill = Perquintill::from_percent(10);
		const MILLISECONDS_PER_YEAR: u64 = 1000 * 3600 * 24 * 36525 / 100;

		runtime_common::impls::era_payout(
			total_staked,
			Nis::issuance().other,
			MAX_ANNUAL_INFLATION,
			Perquintill::from_rational(era_duration_millis, MILLISECONDS_PER_YEAR),
			auctioned_slots,
		)
	}
}

parameter_types! {
	// Six sessions in an era (6 hours).
	pub const SessionsPerEra: SessionIndex = prod_or_fast!(6, 1);

	// 28 eras for unbonding (7 days).
	pub BondingDuration: sp_staking::EraIndex = prod_or_fast!(
		28,
		28,
		"DOT_BONDING_DURATION"
	);
	// 27 eras in which slashes can be cancelled (slightly less than 7 days).
	pub SlashDeferDuration: sp_staking::EraIndex = prod_or_fast!(
		27,
		27,
		"DOT_SLASH_DEFER_DURATION"
	);
	// TODO:(PR#137) - check MaxExposurePageSize/MaxNominators 512?
	pub const MaxExposurePageSize: u32 = 512;
	// Note: this is not really correct as Max Nominators is (MaxExposurePageSize * page_count) but
	// this is an unbounded number. We just set it to a reasonably high value, 1 full page
	// of nominators.
	pub const MaxNominators: u32 = 512;
	pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
	// 24
	pub const MaxNominations: u32 = <NposCompactSolution24 as NposSolution>::LIMIT as u32;
}

impl pallet_staking::Config for Runtime {
	type Currency = Balances;
	type CurrencyBalance = Balance;
	type UnixTime = Timestamp;
	type CurrencyToVote = CurrencyToVote;
	type ElectionProvider = ElectionProviderMultiPhase;
	type GenesisElectionProvider = onchain::OnChainExecution<OnChainSeqPhragmen>;
	type RewardRemainder = Treasury;
	type RuntimeEvent = RuntimeEvent;
	type Slash = Treasury;
	type Reward = ();
	type SessionsPerEra = SessionsPerEra;
	type BondingDuration = BondingDuration;
	type SlashDeferDuration = SlashDeferDuration;
	type AdminOrigin = EitherOf<EnsureRoot<Self::AccountId>, StakingAdmin>;
	type SessionInterface = Self;
	type EraPayout = EraPayout;
	type NextNewSession = Session;
	type MaxExposurePageSize = MaxExposurePageSize;
	type OffendingValidatorsThreshold = OffendingValidatorsThreshold;
	type VoterList = VoterList;
	type TargetList = UseValidatorsMap<Self>;
	type NominationsQuota = pallet_staking::FixedNominationsQuota<{ MaxNominations::get() }>;
	type MaxUnlockingChunks = frame_support::traits::ConstU32<32>;
	type HistoryDepth = frame_support::traits::ConstU32<84>;
	type BenchmarkingConfig = runtime_common::StakingBenchmarkingConfig;
	type EventListeners = NominationPools;
	type WeightInfo = weights::pallet_staking::WeightInfo<Runtime>;
}

impl pallet_fast_unstake::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type BatchSize = frame_support::traits::ConstU32<64>;
	type Deposit = frame_support::traits::ConstU128<{ CENTS * 100 }>;
	type ControlOrigin = EnsureRoot<AccountId>;
	type Staking = Staking;
	type MaxErasToCheckPerBlock = ConstU32<1>;
	type WeightInfo = weights::pallet_fast_unstake::WeightInfo<Runtime>;
}

parameter_types! {
	pub const ProposalBond: Permill = Permill::from_percent(5);
	pub const ProposalBondMinimum: Balance = 2000 * CENTS;
	pub const ProposalBondMaximum: Balance = 1 * GRAND;
	pub const SpendPeriod: BlockNumber = 6 * DAYS;
	pub const Burn: Permill = Permill::from_perthousand(2);
	pub const TreasuryPalletId: PalletId = PalletId(*b"py/trsry");
	pub const PayoutSpendPeriod: BlockNumber = 30 * DAYS;
	// The asset's interior location for the paying account. This is the Treasury
	// pallet instance (which sits at index 18).
	pub TreasuryInteriorLocation: InteriorMultiLocation = PalletInstance(TREASURY_PALLET_ID).into();

	pub const TipCountdown: BlockNumber = 1 * DAYS;
	pub const TipFindersFee: Percent = Percent::from_percent(20);
	pub const TipReportDepositBase: Balance = 100 * CENTS;
	pub const DataDepositPerByte: Balance = 1 * CENTS;
	pub const MaxApprovals: u32 = 100;
	pub const MaxAuthorities: u32 = 100_000;
	pub const MaxKeys: u32 = 10_000;
	pub const MaxPeerInHeartbeats: u32 = 10_000;
}

impl pallet_treasury::Config for Runtime {
	type PalletId = TreasuryPalletId;
	type Currency = Balances;
	type ApproveOrigin = EitherOfDiverse<EnsureRoot<AccountId>, Treasurer>;
	type RejectOrigin = EitherOfDiverse<EnsureRoot<AccountId>, Treasurer>;
	type RuntimeEvent = RuntimeEvent;
	type OnSlash = Treasury;
	type ProposalBond = ProposalBond;
	type ProposalBondMinimum = ProposalBondMinimum;
	type ProposalBondMaximum = ProposalBondMaximum;
	type SpendPeriod = SpendPeriod;
	type Burn = Burn;
	type BurnDestination = Society;
	type MaxApprovals = MaxApprovals;
	type WeightInfo = weights::pallet_treasury::WeightInfo<Runtime>;
	type SpendFunds = Bounties;
	type SpendOrigin = TreasurySpender;
	type AssetKind = VersionedLocatableAsset;
	type Beneficiary = VersionedMultiLocation;
	type BeneficiaryLookup = IdentityLookup<Self::Beneficiary>;
	type Paymaster = PayOverXcm<
		TreasuryInteriorLocation,
		crate::xcm_config::XcmRouter,
		crate::XcmPallet,
		ConstU32<{ 6 * HOURS }>,
		Self::Beneficiary,
		Self::AssetKind,
		LocatableAssetConverter,
		VersionedMultiLocationConverter,
	>;
	type BalanceConverter = AssetRate;
	type PayoutPeriod = PayoutSpendPeriod;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = runtime_common::impls::benchmarks::TreasuryArguments;
}

parameter_types! {
	pub const BountyDepositBase: Balance = 100 * CENTS;
	pub const BountyDepositPayoutDelay: BlockNumber = 4 * DAYS;
	pub const BountyUpdatePeriod: BlockNumber = 90 * DAYS;
	pub const MaximumReasonLength: u32 = 16384;
	pub const CuratorDepositMultiplier: Permill = Permill::from_percent(50);
	pub const CuratorDepositMin: Balance = 10 * CENTS;
	pub const CuratorDepositMax: Balance = 500 * CENTS;
	pub const BountyValueMinimum: Balance = 200 * CENTS;
}

impl pallet_bounties::Config for Runtime {
	type BountyDepositBase = BountyDepositBase;
	type BountyDepositPayoutDelay = BountyDepositPayoutDelay;
	type BountyUpdatePeriod = BountyUpdatePeriod;
	type CuratorDepositMultiplier = CuratorDepositMultiplier;
	type CuratorDepositMin = CuratorDepositMin;
	type CuratorDepositMax = CuratorDepositMax;
	type BountyValueMinimum = BountyValueMinimum;
	type ChildBountyManager = ChildBounties;
	type DataDepositPerByte = DataDepositPerByte;
	type RuntimeEvent = RuntimeEvent;
	type MaximumReasonLength = MaximumReasonLength;
	type WeightInfo = weights::pallet_bounties::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MaxActiveChildBountyCount: u32 = 100;
	pub const ChildBountyValueMinimum: Balance = BountyValueMinimum::get() / 10;
}

impl pallet_child_bounties::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxActiveChildBountyCount = MaxActiveChildBountyCount;
	type ChildBountyValueMinimum = ChildBountyValueMinimum;
	type WeightInfo = weights::pallet_child_bounties::WeightInfo<Runtime>;
}

impl pallet_offences::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
	type OnOffenceHandler = Staking;
}

impl pallet_authority_discovery::Config for Runtime {
	type MaxAuthorities = MaxAuthorities;
}

parameter_types! {
	pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::max_value();
}

impl pallet_im_online::Config for Runtime {
	type AuthorityId = ImOnlineId;
	type RuntimeEvent = RuntimeEvent;
	type ValidatorSet = Historical;
	type NextSessionRotation = Babe;
	type ReportUnresponsiveness = Offences;
	type UnsignedPriority = ImOnlineUnsignedPriority;
	type WeightInfo = weights::pallet_im_online::WeightInfo<Runtime>;
	type MaxKeys = MaxKeys;
	type MaxPeerInHeartbeats = MaxPeerInHeartbeats;
}

parameter_types! {
	pub MaxSetIdSessionEntries: u32 = BondingDuration::get() * SessionsPerEra::get();
}

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;

	type WeightInfo = ();
	type MaxAuthorities = MaxAuthorities;
	type MaxNominators = MaxNominators;
	type MaxSetIdSessionEntries = MaxSetIdSessionEntries;

	type KeyOwnerProof = <Historical as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;

	type EquivocationReportSystem =
		pallet_grandpa::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;
}

/// Submits transaction with the node's public and signature type. Adheres to the signed extension
/// format of the chain.
impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
	RuntimeCall: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: RuntimeCall,
		public: <Signature as Verify>::Signer,
		account: AccountId,
		nonce: <Runtime as frame_system::Config>::Nonce,
	) -> Option<(RuntimeCall, <UncheckedExtrinsic as ExtrinsicT>::SignaturePayload)> {
		use sp_runtime::traits::StaticLookup;
		// take the biggest period possible.
		let period =
			BlockHashCount::get().checked_next_power_of_two().map(|c| c / 2).unwrap_or(2) as u64;

		let current_block = System::block_number()
			.saturated_into::<u64>()
			// The `System::block_number` is initialized with `n+1`,
			// so the actual block number is `n`.
			.saturating_sub(1);
		let tip = 0;
		let extra: SignedExtra = (
			frame_system::CheckNonZeroSender::<Runtime>::new(),
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckMortality::<Runtime>::from(generic::Era::mortal(
				period,
				current_block,
			)),
			frame_system::CheckNonce::<Runtime>::from(nonce),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
		);
		let raw_payload = SignedPayload::new(call, extra)
			.map_err(|e| {
				log::warn!("Unable to create signed payload: {:?}", e);
			})
			.ok()?;
		let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
		let (call, extra, _) = raw_payload.deconstruct();
		let address = <Runtime as frame_system::Config>::Lookup::unlookup(account);
		Some((call, (address, signature, extra)))
	}
}

impl frame_system::offchain::SigningTypes for Runtime {
	type Public = <Signature as Verify>::Signer;
	type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
	RuntimeCall: From<C>,
{
	type Extrinsic = UncheckedExtrinsic;
	type OverarchingCall = RuntimeCall;
}

parameter_types! {
	pub Prefix: &'static [u8] = b"Pay KSMs to the Kusama account:";
}

impl claims::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type VestingSchedule = Vesting;
	type Prefix = Prefix;
	type MoveClaimOrigin = EnsureRoot<AccountId>;
	type WeightInfo = weights::runtime_common_claims::WeightInfo<Runtime>;
}

parameter_types! {
	// Minimum 100 bytes/KSM deposited (1 CENT/byte)
	pub const BasicDeposit: Balance = 1000 * CENTS;       // 258 bytes on-chain
	// TODO:(PR#137) - check ByteDeposit?
	pub const ByteDeposit: Balance = deposit(0, 1);
	pub const SubAccountDeposit: Balance = 200 * CENTS;   // 53 bytes on-chain
	pub const MaxSubAccounts: u32 = 100;
	pub const MaxAdditionalFields: u32 = 100;
	pub const MaxRegistrars: u32 = 20;
}

impl pallet_identity::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type BasicDeposit = BasicDeposit;
	type ByteDeposit = ByteDeposit;
	type SubAccountDeposit = SubAccountDeposit;
	type MaxSubAccounts = MaxSubAccounts;
	type IdentityInformation = IdentityInfo<MaxAdditionalFields>;
	type MaxRegistrars = MaxRegistrars;
	type Slashed = Treasury;
	type ForceOrigin = EitherOf<EnsureRoot<Self::AccountId>, GeneralAdmin>;
	type RegistrarOrigin = EitherOf<EnsureRoot<Self::AccountId>, GeneralAdmin>;
	type WeightInfo = weights::pallet_identity::WeightInfo<Runtime>;
}

impl pallet_utility::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type PalletsOrigin = OriginCaller;
	type WeightInfo = weights::pallet_utility::WeightInfo<Runtime>;
}

parameter_types! {
	// One storage item; key size is 32; value is size 4+4+16+32 bytes = 56 bytes.
	pub const DepositBase: Balance = deposit(1, 88);
	// Additional storage item size of 32 bytes.
	pub const DepositFactor: Balance = deposit(0, 32);
	pub const MaxSignatories: u32 = 100;
}

impl pallet_multisig::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type DepositBase = DepositBase;
	type DepositFactor = DepositFactor;
	type MaxSignatories = MaxSignatories;
	type WeightInfo = weights::pallet_multisig::WeightInfo<Runtime>;
}

parameter_types! {
	pub const ConfigDepositBase: Balance = 500 * CENTS;
	pub const FriendDepositFactor: Balance = 50 * CENTS;
	pub const MaxFriends: u16 = 9;
	pub const RecoveryDeposit: Balance = 500 * CENTS;
}

impl pallet_recovery::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ConfigDepositBase = ConfigDepositBase;
	type FriendDepositFactor = FriendDepositFactor;
	type MaxFriends = MaxFriends;
	type RecoveryDeposit = RecoveryDeposit;
}

parameter_types! {
	pub const SocietyPalletId: PalletId = PalletId(*b"py/socie");
}

impl pallet_society::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type Randomness = pallet_babe::RandomnessFromOneEpochAgo<Runtime>;
	type GraceStrikes = ConstU32<10>;
	type PeriodSpend = ConstU128<{ 500 * QUID }>;
	type VotingPeriod = ConstU32<{ 5 * DAYS }>;
	type ClaimPeriod = ConstU32<{ 2 * DAYS }>;
	type MaxLockDuration = ConstU32<{ 36 * 30 * DAYS }>;
	type FounderSetOrigin = EnsureRoot<AccountId>;
	type ChallengePeriod = ConstU32<{ 7 * DAYS }>;
	type MaxPayouts = ConstU32<8>;
	type MaxBids = ConstU32<512>;
	type PalletId = SocietyPalletId;
	type WeightInfo = weights::pallet_society::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MinVestedTransfer: Balance = 100 * CENTS;
	pub UnvestedFundsAllowedWithdrawReasons: WithdrawReasons =
		WithdrawReasons::except(WithdrawReasons::TRANSFER | WithdrawReasons::RESERVE);
}

impl pallet_vesting::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type BlockNumberToBalance = ConvertInto;
	type MinVestedTransfer = MinVestedTransfer;
	type WeightInfo = weights::pallet_vesting::WeightInfo<Runtime>;
	type UnvestedFundsAllowedWithdrawReasons = UnvestedFundsAllowedWithdrawReasons;
	const MAX_VESTING_SCHEDULES: u32 = 28;
}

parameter_types! {
	// One storage item; key size 32, value size 8; .
	pub const ProxyDepositBase: Balance = deposit(1, 8);
	// Additional storage item size of 33 bytes.
	pub const ProxyDepositFactor: Balance = deposit(0, 33);
	pub const MaxProxies: u16 = 32;
	pub const AnnouncementDepositBase: Balance = deposit(1, 8);
	pub const AnnouncementDepositFactor: Balance = deposit(0, 66);
	pub const MaxPending: u16 = 32;
}

/// The type used to represent the kinds of proxying allowed.
#[derive(
	Copy,
	Clone,
	Eq,
	PartialEq,
	Ord,
	PartialOrd,
	Encode,
	Decode,
	RuntimeDebug,
	MaxEncodedLen,
	TypeInfo,
)]
pub enum ProxyType {
	Any,
	NonTransfer,
	Governance,
	Staking,
	IdentityJudgement,
	CancelProxy,
	Auction,
	Society,
	NominationPools,
}

impl Default for ProxyType {
	fn default() -> Self {
		Self::Any
	}
}

impl InstanceFilter<RuntimeCall> for ProxyType {
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::NonTransfer => matches!(
				c,
				RuntimeCall::System(..) |
				RuntimeCall::Babe(..) |
				RuntimeCall::Timestamp(..) |
				RuntimeCall::Indices(pallet_indices::Call::claim {..}) |
				RuntimeCall::Indices(pallet_indices::Call::free {..}) |
				RuntimeCall::Indices(pallet_indices::Call::freeze {..}) |
				// Specifically omitting Indices `transfer`, `force_transfer`
				// Specifically omitting the entire Balances pallet
				RuntimeCall::Staking(..) |
				RuntimeCall::Session(..) |
				RuntimeCall::Grandpa(..) |
				RuntimeCall::ImOnline(..) |
				RuntimeCall::Treasury(..) |
				RuntimeCall::Bounties(..) |
				RuntimeCall::ChildBounties(..) |
				RuntimeCall::ConvictionVoting(..) |
				RuntimeCall::Referenda(..) |
				RuntimeCall::FellowshipCollective(..) |
				RuntimeCall::FellowshipReferenda(..) |
				RuntimeCall::Whitelist(..) |
				RuntimeCall::Claims(..) |
				RuntimeCall::Utility(..) |
				RuntimeCall::Identity(..) |
				RuntimeCall::Society(..) |
				RuntimeCall::Recovery(pallet_recovery::Call::as_recovered {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::vouch_recovery {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::claim_recovery {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::close_recovery {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::remove_recovery {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::cancel_recovered {..}) |
				// Specifically omitting Recovery `create_recovery`, `initiate_recovery`
				RuntimeCall::Vesting(pallet_vesting::Call::vest {..}) |
				RuntimeCall::Vesting(pallet_vesting::Call::vest_other {..}) |
				// Specifically omitting Vesting `vested_transfer`, and `force_vested_transfer`
				RuntimeCall::Scheduler(..) |
				RuntimeCall::Proxy(..) |
				RuntimeCall::Multisig(..) |
				RuntimeCall::Nis(..) |
				RuntimeCall::Registrar(paras_registrar::Call::register {..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister {..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve {..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..) | // Specifically omitting the entire XCM Pallet
				RuntimeCall::VoterList(..) |
				RuntimeCall::NominationPools(..) |
				RuntimeCall::FastUnstake(..)
			),
			ProxyType::Governance => matches!(
				c,
				RuntimeCall::Treasury(..) |
					RuntimeCall::Bounties(..) |
					RuntimeCall::Utility(..) |
					RuntimeCall::ChildBounties(..) |
					// OpenGov calls
					RuntimeCall::ConvictionVoting(..) |
					RuntimeCall::Referenda(..) |
					RuntimeCall::FellowshipCollective(..) |
					RuntimeCall::FellowshipReferenda(..) |
					RuntimeCall::Whitelist(..)
			),
			ProxyType::Staking => {
				matches!(
					c,
					RuntimeCall::Staking(..) |
						RuntimeCall::Session(..) | RuntimeCall::Utility(..) |
						RuntimeCall::FastUnstake(..) |
						RuntimeCall::VoterList(..) |
						RuntimeCall::NominationPools(..)
				)
			},
			ProxyType::NominationPools => {
				matches!(c, RuntimeCall::NominationPools(..) | RuntimeCall::Utility(..))
			},
			ProxyType::IdentityJudgement => matches!(
				c,
				RuntimeCall::Identity(pallet_identity::Call::provide_judgement { .. }) |
					RuntimeCall::Utility(..)
			),
			ProxyType::CancelProxy => {
				matches!(c, RuntimeCall::Proxy(pallet_proxy::Call::reject_announcement { .. }))
			},
			ProxyType::Auction => matches!(
				c,
				RuntimeCall::Auctions(..) |
					RuntimeCall::Crowdloan(..) |
					RuntimeCall::Registrar(..) |
					RuntimeCall::Slots(..)
			),
			ProxyType::Society => matches!(c, RuntimeCall::Society(..)),
		}
	}
	fn is_superset(&self, o: &Self) -> bool {
		match (self, o) {
			(x, y) if x == y => true,
			(ProxyType::Any, _) => true,
			(_, ProxyType::Any) => false,
			(ProxyType::NonTransfer, _) => true,
			_ => false,
		}
	}
}

impl pallet_proxy::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ProxyType = ProxyType;
	type ProxyDepositBase = ProxyDepositBase;
	type ProxyDepositFactor = ProxyDepositFactor;
	type MaxProxies = MaxProxies;
	type WeightInfo = weights::pallet_proxy::WeightInfo<Runtime>;
	type MaxPending = MaxPending;
	type CallHasher = BlakeTwo256;
	type AnnouncementDepositBase = AnnouncementDepositBase;
	type AnnouncementDepositFactor = AnnouncementDepositFactor;
}

impl parachains_origin::Config for Runtime {}

impl parachains_configuration::Config for Runtime {
	type WeightInfo = weights::runtime_parachains_configuration::WeightInfo<Runtime>;
}

impl parachains_shared::Config for Runtime {}

impl parachains_session_info::Config for Runtime {
	type ValidatorSet = Historical;
}

impl parachains_inclusion::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type DisputesHandler = ParasDisputes;
	type RewardValidators = parachains_reward_points::RewardValidatorsWithEraPoints<Runtime>;
	type MessageQueue = MessageQueue;
	type WeightInfo = weights::runtime_parachains_inclusion::WeightInfo<Runtime>;
}

parameter_types! {
	pub const ParasUnsignedPriority: TransactionPriority = TransactionPriority::max_value();
}

impl parachains_paras::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::runtime_parachains_paras::WeightInfo<Runtime>;
	type UnsignedPriority = ParasUnsignedPriority;
	type QueueFootprinter = ParaInclusion;
	type NextSessionRotation = Babe;
	type OnNewHead = Registrar;
}

parameter_types! {
	/// Amount of weight that can be spent per block to service messages.
	///
	/// # WARNING
	///
	/// This is not a good value for para-chains since the `Scheduler` already uses up to 80% block weight.
	pub MessageQueueServiceWeight: Weight = Perbill::from_percent(20) * BlockWeights::get().max_block;
	pub const MessageQueueHeapSize: u32 = 65_536;
	pub const MessageQueueMaxStale: u32 = 16;
}

/// Message processor to handle any messages that were enqueued into the `MessageQueue` pallet.
pub struct MessageProcessor;
impl ProcessMessage for MessageProcessor {
	type Origin = AggregateMessageOrigin;

	fn process_message(
		message: &[u8],
		origin: Self::Origin,
		meter: &mut WeightMeter,
		id: &mut [u8; 32],
	) -> Result<bool, ProcessMessageError> {
		let para = match origin {
			AggregateMessageOrigin::Ump(UmpQueueId::Para(para)) => para,
		};
		xcm_builder::ProcessXcmMessage::<
			Junction,
			xcm_executor::XcmExecutor<xcm_config::XcmConfig>,
			RuntimeCall,
		>::process_message(message, Junction::Parachain(para.into()), meter, id)
	}
}

impl pallet_message_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Size = u32;
	type HeapSize = MessageQueueHeapSize;
	type MaxStale = MessageQueueMaxStale;
	type ServiceWeight = MessageQueueServiceWeight;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type MessageProcessor = MessageProcessor;
	#[cfg(feature = "runtime-benchmarks")]
	type MessageProcessor =
		pallet_message_queue::mock_helpers::NoopMessageProcessor<AggregateMessageOrigin>;
	type QueueChangeHandler = ParaInclusion;
	type QueuePausedQuery = ();
	type WeightInfo = weights::pallet_message_queue::WeightInfo<Runtime>;
}

impl parachains_dmp::Config for Runtime {}

impl parachains_hrmp::Config for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeEvent = RuntimeEvent;
	type ChannelManager = EitherOf<EnsureRoot<Self::AccountId>, GeneralAdmin>;
	type Currency = Balances;
	type WeightInfo = weights::runtime_parachains_hrmp::WeightInfo<Runtime>;
}

impl parachains_paras_inherent::Config for Runtime {
	type WeightInfo = weights::runtime_parachains_paras_inherent::WeightInfo<Runtime>;
}

impl parachains_scheduler::Config for Runtime {
	type AssignmentProvider = ParaAssignmentProvider;
}

impl parachains_assigner_parachains::Config for Runtime {}

impl parachains_initializer::Config for Runtime {
	type Randomness = pallet_babe::RandomnessFromOneEpochAgo<Runtime>;
	type ForceOrigin = EnsureRoot<AccountId>;
	type WeightInfo = weights::runtime_parachains_initializer::WeightInfo<Runtime>;
}

impl parachains_disputes::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RewardValidators = parachains_reward_points::RewardValidatorsWithEraPoints<Runtime>;
	type SlashingHandler = parachains_slashing::SlashValidatorsForDisputes<ParasSlashing>;
	type WeightInfo = weights::runtime_parachains_disputes::WeightInfo<Runtime>;
}

impl parachains_slashing::Config for Runtime {
	type KeyOwnerProofSystem = Historical;
	type KeyOwnerProof =
		<Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(KeyTypeId, ValidatorId)>>::Proof;
	type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
		KeyTypeId,
		ValidatorId,
	)>>::IdentificationTuple;
	type HandleReports = parachains_slashing::SlashingReportHandler<
		Self::KeyOwnerIdentification,
		Offences,
		ReportLongevity,
	>;
	type WeightInfo = weights::runtime_parachains_disputes_slashing::WeightInfo<Runtime>;
	type BenchmarkingConfig = parachains_slashing::BenchConfig<1000>;
}

parameter_types! {
	pub const ParaDeposit: Balance = 40 * UNITS;
}

impl paras_registrar::Config for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type OnSwap = (Crowdloan, Slots);
	type ParaDeposit = ParaDeposit;
	type DataDepositPerByte = DataDepositPerByte;
	type WeightInfo = weights::runtime_common_paras_registrar::WeightInfo<Runtime>;
}

parameter_types! {
	// 6 weeks
	pub LeasePeriod: BlockNumber = prod_or_fast!(6 * WEEKS, 6 * WEEKS, "KSM_LEASE_PERIOD");
}

impl slots::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type Registrar = Registrar;
	type LeasePeriod = LeasePeriod;
	type LeaseOffset = ();
	type ForceOrigin = EitherOf<EnsureRoot<Self::AccountId>, LeaseAdmin>;
	type WeightInfo = weights::runtime_common_slots::WeightInfo<Runtime>;
}

parameter_types! {
	pub const CrowdloanId: PalletId = PalletId(*b"py/cfund");
	pub const OldSubmissionDeposit: Balance = 3 * GRAND; // ~ 10 KSM
	pub const MinContribution: Balance = 3_000 * CENTS; // ~ .1 KSM
	pub const RemoveKeysLimit: u32 = 1000;
	// Allow 32 bytes for an additional memo to a crowdloan.
	pub const MaxMemoLength: u8 = 32;
}

impl crowdloan::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type PalletId = CrowdloanId;
	type SubmissionDeposit = OldSubmissionDeposit;
	type MinContribution = MinContribution;
	type RemoveKeysLimit = RemoveKeysLimit;
	type Registrar = Registrar;
	type Auctioneer = Auctions;
	type MaxMemoLength = MaxMemoLength;
	type WeightInfo = weights::runtime_common_crowdloan::WeightInfo<Runtime>;
}

parameter_types! {
	// The average auction is 7 days long, so this will be 70% for ending period.
	// 5 Days = 72000 Blocks @ 6 sec per block
	pub const EndingPeriod: BlockNumber = 5 * DAYS;
	// ~ 1000 samples per day -> ~ 20 blocks per sample -> 2 minute samples
	pub const SampleLength: BlockNumber = 2 * MINUTES;
}

impl auctions::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Leaser = Slots;
	type Registrar = Registrar;
	type EndingPeriod = EndingPeriod;
	type SampleLength = SampleLength;
	type Randomness = pallet_babe::RandomnessFromOneEpochAgo<Runtime>;
	type InitiateOrigin = EitherOf<EnsureRoot<Self::AccountId>, AuctionAdmin>;
	type WeightInfo = weights::runtime_common_auctions::WeightInfo<Runtime>;
}

type NisCounterpartInstance = pallet_balances::Instance2;
impl pallet_balances::Config<NisCounterpartInstance> for Runtime {
	type Balance = Balance;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ConstU128<10_000_000_000>; // One KTC cent
	type AccountStore = StorageMapShim<
		pallet_balances::Account<Runtime, NisCounterpartInstance>,
		AccountId,
		pallet_balances::AccountData<u128>,
	>;
	type MaxLocks = ConstU32<4>;
	type MaxReserves = ConstU32<4>;
	type ReserveIdentifier = [u8; 8];
	type WeightInfo = weights::pallet_balances_nis::WeightInfo<Runtime>;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type FreezeIdentifier = ();
	type MaxHolds = ConstU32<2>;
	type MaxFreezes = ConstU32<1>;
}

parameter_types! {
	pub const NisBasePeriod: BlockNumber = 7 * DAYS;
	pub const MinBid: Balance = 100 * QUID;
	pub MinReceipt: Perquintill = Perquintill::from_rational(1u64, 10_000_000u64);
	pub const IntakePeriod: BlockNumber = 5 * MINUTES;
	pub MaxIntakeWeight: Weight = MAXIMUM_BLOCK_WEIGHT / 10;
	pub const ThawThrottle: (Perquintill, BlockNumber) = (Perquintill::from_percent(25), 5);
	pub storage NisTarget: Perquintill = Perquintill::zero();
	pub const NisPalletId: PalletId = PalletId(*b"py/nis  ");
}

impl pallet_nis::Config for Runtime {
	type WeightInfo = weights::pallet_nis::WeightInfo<Runtime>;
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type CurrencyBalance = Balance;
	type FundOrigin = frame_system::EnsureSigned<AccountId>;
	type Counterpart = NisCounterpartBalances;
	type CounterpartAmount = WithMaximumOf<ConstU128<21_000_000_000_000_000_000u128>>;
	type Deficit = (); // Mint
	type IgnoredIssuance = ();
	type Target = NisTarget;
	type PalletId = NisPalletId;
	type QueueCount = ConstU32<500>;
	type MaxQueueLen = ConstU32<1000>;
	type FifoQueueLen = ConstU32<250>;
	type BasePeriod = NisBasePeriod;
	type MinBid = MinBid;
	type MinReceipt = MinReceipt;
	type IntakePeriod = IntakePeriod;
	type MaxIntakeWeight = MaxIntakeWeight;
	type ThawThrottle = ThawThrottle;
	type RuntimeHoldReason = RuntimeHoldReason;
}

parameter_types! {
	pub const PoolsPalletId: PalletId = PalletId(*b"py/nopls");
	pub const MaxPointsToBalance: u8 = 10;
}

impl pallet_nomination_pools::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::pallet_nomination_pools::WeightInfo<Self>;
	type Currency = Balances;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type RewardCounter = FixedU128;
	type BalanceToU256 = BalanceToU256;
	type U256ToBalance = U256ToBalance;
	type Staking = Staking;
	type PostUnbondingPoolsWindow = ConstU32<4>;
	type MaxMetadataLen = ConstU32<256>;
	// we use the same number of allowed unlocking chunks as with staking.
	type MaxUnbonding = <Self as pallet_staking::Config>::MaxUnlockingChunks;
	type PalletId = PoolsPalletId;
	type MaxPointsToBalance = MaxPointsToBalance;
}

parameter_types! {
	// The deposit configuration for the singed migration. Specially if you want to allow any signed account to do the migration (see `SignedFilter`, these deposits should be high)
	pub const MigrationSignedDepositPerItem: Balance = 1 * CENTS;
	pub const MigrationSignedDepositBase: Balance = 20 * CENTS * 100;
	pub const MigrationMaxKeyLen: u32 = 512;
}

impl pallet_state_trie_migration::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type SignedDepositPerItem = MigrationSignedDepositPerItem;
	type SignedDepositBase = MigrationSignedDepositBase;
	type ControlOrigin = EnsureRoot<AccountId>;
	type SignedFilter = frame_support::traits::NeverEnsureOrigin<AccountId>;

	// Use same weights as substrate ones.
	type WeightInfo = pallet_state_trie_migration::weights::SubstrateWeight<Runtime>;
	type MaxKeyLen = MigrationMaxKeyLen;
}

impl pallet_asset_rate::Config for Runtime {
	type WeightInfo = weights::pallet_asset_rate::WeightInfo<Runtime>;
	type RuntimeEvent = RuntimeEvent;
	type CreateOrigin = EitherOfDiverse<EnsureRoot<AccountId>, Treasurer>;
	type RemoveOrigin = EitherOfDiverse<EnsureRoot<AccountId>, Treasurer>;
	type UpdateOrigin = EitherOfDiverse<EnsureRoot<AccountId>, Treasurer>;
	type Currency = Balances;
	type AssetKind = <Runtime as pallet_treasury::Config>::AssetKind;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = runtime_common::impls::benchmarks::AssetRateArguments;
}

construct_runtime! {
	pub enum Runtime
	{
		// Basic stuff; balances is uncallable initially.
		System: frame_system::{Pallet, Call, Storage, Config<T>, Event<T>} = 0,

		// Babe must be before session.
		Babe: pallet_babe::{Pallet, Call, Storage, Config<T>, ValidateUnsigned} = 1,

		Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent} = 2,
		Indices: pallet_indices::{Pallet, Call, Storage, Config<T>, Event<T>} = 3,
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>} = 4,
		TransactionPayment: pallet_transaction_payment::{Pallet, Storage, Event<T>} = 33,

		// Consensus support.
		// Authorship must be before session in order to note author in the correct session and era
		// for im-online and staking.
		Authorship: pallet_authorship::{Pallet, Storage} = 5,
		Staking: pallet_staking::{Pallet, Call, Storage, Config<T>, Event<T>} = 6,
		Offences: pallet_offences::{Pallet, Storage, Event} = 7,
		Historical: session_historical::{Pallet} = 34,

		// BEEFY Bridges support.
		Beefy: pallet_beefy::{Pallet, Call, Storage, Config<T>, ValidateUnsigned} = 200,
		// MMR leaf construction must be before session in order to have leaf contents
		// refer to block<N-1> consistently. see substrate issue #11797 for details.
		Mmr: pallet_mmr::{Pallet, Storage} = 201,
		BeefyMmrLeaf: pallet_beefy_mmr::{Pallet, Storage} = 202,

		Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>} = 8,
		Grandpa: pallet_grandpa::{Pallet, Call, Storage, Config<T>, Event, ValidateUnsigned} = 10,
		ImOnline: pallet_im_online::{Pallet, Call, Storage, Event<T>, ValidateUnsigned, Config<T>} = 11,
		AuthorityDiscovery: pallet_authority_discovery::{Pallet, Config<T>} = 12,

		// Governance stuff.
		Treasury: pallet_treasury::{Pallet, Call, Storage, Config<T>, Event<T>} = 18,
		ConvictionVoting: pallet_conviction_voting::{Pallet, Call, Storage, Event<T>} = 20,
		Referenda: pallet_referenda::{Pallet, Call, Storage, Event<T>} = 21,
//		pub type FellowshipCollectiveInstance = pallet_ranked_collective::Instance1;
		FellowshipCollective: pallet_ranked_collective::<Instance1>::{
			Pallet, Call, Storage, Event<T>
		} = 22,
//		pub type FellowshipReferendaInstance = pallet_referenda::Instance2;
		FellowshipReferenda: pallet_referenda::<Instance2>::{
			Pallet, Call, Storage, Event<T>
		} = 23,
		Origins: pallet_custom_origins::{Origin} = 43,
		Whitelist: pallet_whitelist::{Pallet, Call, Storage, Event<T>} = 44,

		// Claims. Usable initially.
		Claims: claims::{Pallet, Call, Storage, Event<T>, Config<T>, ValidateUnsigned} = 19,

		// Utility module.
		Utility: pallet_utility::{Pallet, Call, Event} = 24,

		// Less simple identity module.
		Identity: pallet_identity::{Pallet, Call, Storage, Event<T>} = 25,

		// Society module.
		Society: pallet_society::{Pallet, Call, Storage, Event<T>} = 26,

		// Social recovery module.
		Recovery: pallet_recovery::{Pallet, Call, Storage, Event<T>} = 27,

		// Vesting. Usable initially, but removed once all vesting is finished.
		Vesting: pallet_vesting::{Pallet, Call, Storage, Event<T>, Config<T>} = 28,

		// System scheduler.
		Scheduler: pallet_scheduler::{Pallet, Call, Storage, Event<T>} = 29,

		// Proxy module. Late addition.
		Proxy: pallet_proxy::{Pallet, Call, Storage, Event<T>} = 30,

		// Multisig module. Late addition.
		Multisig: pallet_multisig::{Pallet, Call, Storage, Event<T>} = 31,

		// Preimage registrar.
		Preimage: pallet_preimage::{Pallet, Call, Storage, Event<T>, HoldReason} = 32,

		// Bounties modules.
		Bounties: pallet_bounties::{Pallet, Call, Storage, Event<T>} = 35,
		ChildBounties: pallet_child_bounties = 40,

		// Election pallet. Only works with staking, but placed here to maintain indices.
		ElectionProviderMultiPhase: pallet_election_provider_multi_phase::{Pallet, Call, Storage, Event<T>, ValidateUnsigned} = 37,

		// NIS pallet.
		Nis: pallet_nis::{Pallet, Call, Storage, Event<T>, HoldReason} = 38,
		NisCounterpartBalances: pallet_balances::<Instance2> = 45,

		// Provides a semi-sorted list of nominators for staking.
		VoterList: pallet_bags_list::<Instance1>::{Pallet, Call, Storage, Event<T>} = 39,

		// nomination pools: extension to staking.
		NominationPools: pallet_nomination_pools::{Pallet, Call, Storage, Event<T>, Config<T>, FreezeReason} = 41,

		// Fast unstake pallet: extension to staking.
		FastUnstake: pallet_fast_unstake = 42,

		// Parachains pallets. Start indices at 50 to leave room.
		ParachainsOrigin: parachains_origin::{Pallet, Origin} = 50,
		Configuration: parachains_configuration::{Pallet, Call, Storage, Config<T>} = 51,
		ParasShared: parachains_shared::{Pallet, Call, Storage} = 52,
		ParaInclusion: parachains_inclusion::{Pallet, Call, Storage, Event<T>} = 53,
		ParaInherent: parachains_paras_inherent::{Pallet, Call, Storage, Inherent} = 54,
		ParaScheduler: parachains_scheduler::{Pallet, Storage} = 55,
		Paras: parachains_paras::{Pallet, Call, Storage, Event, Config<T>, ValidateUnsigned} = 56,
		Initializer: parachains_initializer::{Pallet, Call, Storage} = 57,
		Dmp: parachains_dmp::{Pallet, Storage} = 58,
		Hrmp: parachains_hrmp::{Pallet, Call, Storage, Event<T>, Config<T>} = 60,
		ParaSessionInfo: parachains_session_info::{Pallet, Storage} = 61,
		ParasDisputes: parachains_disputes::{Pallet, Call, Storage, Event<T>} = 62,
		ParasSlashing: parachains_slashing::{Pallet, Call, Storage, ValidateUnsigned} = 63,
		ParaAssignmentProvider: parachains_assigner_parachains::{Pallet, Storage} = 64,

		// Parachain Onboarding Pallets. Start indices at 70 to leave room.
		Registrar: paras_registrar::{Pallet, Call, Storage, Event<T>} = 70,
		Slots: slots::{Pallet, Call, Storage, Event<T>} = 71,
		Auctions: auctions::{Pallet, Call, Storage, Event<T>} = 72,
		Crowdloan: crowdloan::{Pallet, Call, Storage, Event<T>} = 73,

		// State trie migration pallet, only temporary.
		StateTrieMigration: pallet_state_trie_migration = 98,

		// Pallet for sending XCM.
		XcmPallet: pallet_xcm::{Pallet, Call, Storage, Event<T>, Origin, Config<T>} = 99,

		// Generalized message queue
		MessageQueue: pallet_message_queue::{Pallet, Call, Storage, Event<T>} = 100,

		// Asset rate.
		AssetRate: pallet_asset_rate::{Pallet, Call, Storage, Event<T>} = 101,
	}
}

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// `BlockId` type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// The `SignedExtension` to the basic transaction logic.
pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckMortality<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

pub struct NominationPoolsMigrationV4OldPallet;
impl Get<Perbill> for NominationPoolsMigrationV4OldPallet {
	fn get() -> Perbill {
		Perbill::from_percent(10)
	}
}

/// All migrations that will run on the next runtime upgrade.
///
/// This contains the combined migrations of the last 10 releases. It allows to skip runtime
/// upgrades in case governance decides to do so. THE ORDER IS IMPORTANT.
pub type Migrations = migrations::Unreleased;

/// The runtime migrations per release.
#[allow(deprecated, missing_docs)]
pub mod migrations {
	use super::{parachains_configuration, Runtime};

	/// Sanity check that the session keys slated to remove are not part of the active validator
	/// set.
	mod check_session_keys {
		use super::*;
		use frame_election_provider_support::Weight;
		use frame_support::weights::constants::RocksDbWeight;
		use hex_literal::hex;

		pub struct Migration;

		const KEYS: [[u8; 32]; 381] = [
			hex!("00671772a67fddd99e179ea4c704d93eb6f948a1739c4698c63ca46301910c37"),
			hex!("00d826c844d2bba830023d59c153e2e8a94b070f4488d6518a3acd0fa933dbc0"),
			hex!("01962a2f00906d07a8b932cf7e23dd3bac4296d4d78a7fc7a6b778995d7b1770"),
			hex!("01b9df2dcd4b0e81e6b84dd7f07b74387d48aed63902e46165d0e5ea2bce8205"),
			hex!("01bfa90a8ca401e85c14d2ec5edcdbcb287f62a38aedb78d6d76b85a7f16dbf2"),
			hex!("029806cde27f7ed49aa001497f9aa1f495971781cab4994ecc0fc71e7680fda4"),
			hex!("03059e73ce795f8b2b886804eeb2b907f253cdda6ac87506b6180e3a9ba3dfbe"),
			hex!("054b38aecd7e1655bc103764456f15790c3531b2238abf956abba274ed28e8c4"),
			hex!("075b928a4b4f6cc8f5d0015a20e1938cffe7f9190b352f0892e61aec879870a6"),
			hex!("078bae9d7e8a6cdb1e03418983cb53e9b9eb0bb61d639cccb9e9eb0154dc9666"),
			hex!("07e925b78955913ae0a7284d4d189bf00e391ed230db243ee975b45965477ecb"),
			hex!("08083e9b6bba699f313ea9cce1d2fa9090a4fa3ebd56137c912f9b97fc13e604"),
			hex!("09734c60700575fcc4a0da417f91b9a1ea9e5c965f29e9075c3e014cc95998b6"),
			hex!("09ec954f000fd0c125227d990364f01c2887dcefed30136071fa93995cdfeabc"),
			hex!("0a4fbca2f2592ed199d6eb8a5ea8cbd14f250bd31d482eb9f248a9df43fa24ee"),
			hex!("0a925a1a92be3d89b3d268782877903d3e5a7b3ebddd9852bd2525ba68da8729"),
			hex!("0ab773fd5dabc462805942e8bc7f7653f6c39b917c997fe1f1850a9e14ca28c8"),
			hex!("0bad734ad68dd7178fb7f740fa3d47bb78c934e84e7dd6d1d1705cc131fcb79c"),
			hex!("0bb34ce88e9136b0a027aaea1b6516fc287097b46404c891a4fac973a3998619"),
			hex!("0c5ec4646b89f1ae7027bc4bebe17e399390c302e2c338ab629c2164b14fa730"),
			hex!("0dadfaab76ad5125f2f00cbfc007da99497691ed17d0b210bb398b0e0df34128"),
			hex!("0e6aaa1e6fda86d67c8d37e4ee63e01ed8464332de5cc8079ff0c65799e83709"),
			hex!("0f1bab80e805877f676cab54e02bb7f2a9484e7e280fe592f6d4cdd424aaedc6"),
			hex!("0f712890029f650222535575fc5946019026beeef1c2d82196ea5c6fe6a787b0"),
			hex!("0ff736207e32035c2388d7fc782435f3f6d5284f7e8938329aa62d68646e4e64"),
			hex!("105e0a531735a52f3c2fd1f05cea7f72b211c0e94a4548f1d495ba52102bfbd2"),
			hex!("116318404807c2782455808c97f7061855b37356cd4087930fe8868df16207d2"),
			hex!("11c5bff33dad6ac6a35efde045d63638034629510d54969f55eceb61472674a6"),
			hex!("127e01ec910952ceaf880274f705acfb9c8637c6f021de84a0769da6f9c51f2e"),
			hex!("130251e627f042a2f5d25f88fe7b4a79fd969e4611dbcfebb1e679665351f454"),
			hex!("13505e5dd30ea1e5b79257814fec58c6620e16c32855b7d9699685ea9aeea39f"),
			hex!("137548c71edcca875d889aa0b278b4961caaa01bb40cbff030dcf208d8086b58"),
			hex!("139d2ceb586ad4c40f58aed713642561e2c9277ec9ddb9222147d15630cf34cc"),
			hex!("13a1aa0efe1e058bad1d3240bddad216ab2760c7591c00562f85cbfe90b1368f"),
			hex!("140de8e513166ed3ee596ecbcf547d5526fe12288ab4ef12500cfd05dc5f7a7b"),
			hex!("149def72f6de8f8f7033a0c4a0b88b8265e799b87d8dbcecfe558eb5061cdf0c"),
			hex!("15a96ce60585a9dbd2db0568b7264b0f1e26c262da0b4a130314c492c279fb51"),
			hex!("17a059aed160e9dcdc0e0e88c27ae526b2dee7f7b8055aeb835798866ea77bd1"),
			hex!("17a8c57326ffd99bb20833b3688f6a17290ae565bf91c6348dc2e64e0b339cff"),
			hex!("17f6c900a05eae9875292f5a9e775c19721824bb2c53c5e15985237d197dc163"),
			hex!("185991e3eaddf311ebc1f06314a73571ffe74f4fb643117931b32a25b432401f"),
			hex!("18b10c7c871328fa807a41bc9420a3c272550d82b8af97316de09d74d013276a"),
			hex!("18ff0237f98c74fdc71cec3a9de17eadce4e340732f1a38d9be8ac25790633a4"),
			hex!("1932680cd17166acd08c9559cca5c7233262b7a44b830868cbbc90e9050425ab"),
			hex!("19594741bda9dd66cc51748000fae6a8661a482f0f8aeaf578158d132912b22a"),
			hex!("1bea624233651efa71e46133a11725dbb9a20c16b5cbac9083e9e111cd765065"),
			hex!("1bfed7957cf1be7d3fc9ef94f107311c1f32d839cad8e69ac7e0cdd2f9487999"),
			hex!("1c5d41987d2eec3880ecf0ae1d673cd1f6625e00130187db58770e5df5e9589b"),
			hex!("1c79538fb87a09de261557bc1de0720c0fe3295b4dcaa78611f93b02c14188c5"),
			hex!("1e97d0a59df4d86d35f70d2e738ca1d3e1c540bea3f6d8548a90f6c8759a1338"),
			hex!("1f0576834f09b7ddbc5f575d101ed7854908bced969e1f2132de083648f55a03"),
			hex!("1f473e7f699be54b1c905fad682175f2d704bde7207f38179fa68bbcb951a40d"),
			hex!("1fed2dd7e67394a3a62436da2c8078f196f8cdac81d48fbd47e3c3c7e56686d7"),
			hex!("20f1e0547888f0db7a831388453dda97d89de89334175ad41f66bc129bb89a37"),
			hex!("23c0cb073478968026ddc16d75cb2724df7ec7057ac2c113af3e98578671fb94"),
			hex!("2428211f4e4a570edd36ca19ebc1d713025a0d10c25f1c35a06ee4f0d56dcdb8"),
			hex!("254139e560cf858842643a75c3019dd732d11a62a18c599f9ce6222da62dd2d0"),
			hex!("256b109e727d773f639946e6ee9ceb167e716f1c368c8ff2101c363734b87fdc"),
			hex!("257951c7344f1a577ec848300d1bebfb5c66c323b10a41ad285af58c7a441c06"),
			hex!("260ad507bd86487901241c63af704ac564c705f5b3110fbe69ff660c6e52b433"),
			hex!("2627ad7baea2482a0f7103821523438c658a4bf29cd3307271113240b90a7b96"),
			hex!("2636557e785a85bbfeb9f3580144bf08f6afc892198361e625c9f3055d76b415"),
			hex!("26be58719c0d4a4c5e0de508b1ec0c5455d2bc448ccf92949a7a794d8a004c23"),
			hex!("279a5dcfc1892ade31c08b3d4824b53c41ab28035d072d54130bcb7ba7efa3f0"),
			hex!("27d9fcb195b77d17482309000d6a530fa762ab9566b9038bc812f40937ba8dbe"),
			hex!("28039493f2bba35a27e050424eda7d6513d4877cc19fff65c5fc5b56a21f1be9"),
			hex!("28315c2d5cee2a325d4c1e97793d984d493eea52f986c958ff678cc39cc54fce"),
			hex!("2839b5c66130bbf248eeea3aaba10262ccd47782ff7fa5812f60217fb63becbb"),
			hex!("283bd7994e0a484dfc0fd147250ba6727f005cbdc9c345b562ea21ab24711d6d"),
			hex!("284d8620e92c618daef16a08737d4b77c85ea93eff8243f93aa283a42917fdf5"),
			hex!("29a68a460d2a0ca383ab179221cbd98dfbe010a941a29d451894f916ef55a4ad"),
			hex!("2a393bd53577bde0ad2dcdbf8257ad3f5149806069a9365b2037ac704c7fad48"),
			hex!("2af699357c8556830b312cb42271bb0eaa3ed4c0e38f189171a4723913ffe015"),
			hex!("2d1f323f23efbbc6f1fe191c1309841b232a067c764e64cf94940ef1c38a6ac8"),
			hex!("2d72097527d70a39af9763247af2e30ba9d23fe349f119ebda6395a7486777fd"),
			hex!("2de18b2f9ed87d4b71d26ff8585c127dcd765eae5b3683bc3529b8506c64ef84"),
			hex!("2e3d447409e23dda6ccd0e5521e485e0f0c00b1ff0cb87457db88b2c66bb8c9e"),
			hex!("2f51b6d3b1bf6bb8b889c149c5132fb0ab0cf74cf3994a36f8938e0007156de6"),
			hex!("3255e1f0881b2d8e4670d13bf0ea8302ef9d97f1e186e475f66894af2a119360"),
			hex!("32a6be87b189eabd4f8cebe7af647ee396e8db630e32e89aa898f8f81cbc2345"),
			hex!("32d249fbbc8d3c6ac6f2e6a47f672c9fa1bd01f120d2ed9704a3502a03ac3c9a"),
			hex!("33d741b7d98ef2b37fecb9daf1bb48a3081c14eb42e78513f57b41f3e293687b"),
			hex!("34438ae6719e63f578ae86639de2ee186e19738cc3057f7ea8abb083e49db208"),
			hex!("34770d80ce293ce5dfdff08042f6eeff9c3db1ff71ebc67291364d51ee52a4a3"),
			hex!("34eb500d3eef94237b01080d6dd35690a662873669b6f52f840a7bbca0b9c56b"),
			hex!("3535f44f0057c8ae00c0e692b05154833401f51c5ad1b90ea63454ed724752ba"),
			hex!("3559a4a79263d39462d203097dd439b2f7f6c8107c4bc4a19dd85dea35610699"),
			hex!("3652897f705c2c6859548b7b9843c9251a87cbc54fc170b3ee4efd7e2b4c96c6"),
			hex!("368f39ad355d5699cae9779a9cbda76b9ef864ad87f3600ffc99d344b16922b5"),
			hex!("3747f2509123c6af0437dd10f14ada3bbfce33d1cdb7e98d0d42e9b75bacdff0"),
			hex!("37ea72cbcbd3b60d245a0d7fdf069384645a0ae0f28bcddb386cb3755e15926f"),
			hex!("38b72fc06d04eb63872bc7299adafea57741df5229adb4992af9014f294e279c"),
			hex!("39977c9ec0d9546ceed6b446519a7bcb0b69861406e478daa18c1197a46981be"),
			hex!("3ac9f327678ee5608c250583a9c53ffb9ff2b396c82730e8e5c58aadf639b265"),
			hex!("3b685f3b38b33336af2a0e530b5fa7cceec91d4a36f784c183d65b5e30dff3a6"),
			hex!("3bf5ad9c63be8730ee493d32b1df909e52cf64db4118b568a638f06bbc14cb45"),
			hex!("3d6bfd5537e35f1ee65b8dd08d253cad6671cb3a0cff784793617ac3fedf6b2b"),
			hex!("3dc14be39dc9f16f965f85029e20acfa4d960869eeb01b8b32691cfbc8ae4bb2"),
			hex!("3de9e072def4b1994b3bb7beb87a610e3120dab2036388ea0000dd0555e0c47a"),
			hex!("3e2b0bc69277556f0156cff5f274d855425947a332314bcda663f50baaf93f1f"),
			hex!("3f07745508b7421f37c193eadebf191dc9b721296b4b506c0757c3fdae51ee75"),
			hex!("3f8feeba5be66fe8e4010ea18f3072d719b07097a447d013fe09e273be239528"),
			hex!("3fb45dca94a2cf74c3b49a58379298aa6876bc8c199b5b287a86f7e229975d2c"),
			hex!("3fdc719360471b7d8900940f8e779bbdfb353238fec7e90400eee76e68f621e5"),
			hex!("4356429cd1205ce28b1bd3d1b81a6d04990138db5c3a4018e66a37a2540123af"),
			hex!("43b566219601f5703c90fdf677d5cd82a62fda39f890983d2948f2a6df184079"),
			hex!("4436e2ea73b6cc84dfc025a5970f12a2e44a15c2ea3ae3b4a0bd3717961b2fa5"),
			hex!("443c535550f1e52f98b1fb063503c75e1f582323f3ae14364c1baa8b776c066d"),
			hex!("445dd764238a265921feb6a24c5bf549b5895102db9f4dbb17439af91100a43c"),
			hex!("44c37057b912f3f317dff034cdba198a836c08b5e07e58d9845aea645830b646"),
			hex!("44d5c8171f0f2a89b5f054521ff0ffe4ffbd0e08516d2adcda90310b6b45b465"),
			hex!("471e2556bb5b6185e6b80ae6944773727131afe475b3606487725c3d74deb9bc"),
			hex!("4924d02d5767dbaff2224a36e4c4d3a756d85ac5f5b174022d18ee7c2093a1a0"),
			hex!("4a6d054300d54e5e62f3830bc45cea4e0192121c3a8f6943358ff34d933982a4"),
			hex!("4b00045ed16c8390915e979539328d34a9a53435f81f5db4c0b331b6c10d9b50"),
			hex!("4bde4622bcd16b2aa305873016a6a98b1b2400aa493578055e014dd0980932a0"),
			hex!("4d847a30f25bdcc016574953cc37925472deb9c75b5f957e1adb0d13c82394b1"),
			hex!("4dc05825226ad3d4a7df2cabd0337cbce99b0971a907f47dade10831c077fb13"),
			hex!("4dedec40b2d004f8cf0406d82279c910f3b258987cbf3cd4b33e373d52f6e5af"),
			hex!("4e08ad13e25873f4a3f2188798a74fc52cb88b4c9a352a10efb43f86a4c84b91"),
			hex!("4e299eabb9590734c03b7aaf1fe50d7a909e2979cc06ddcb8a672f766743853a"),
			hex!("4f8d18e4029465b8b4e07724ba8b2794c266c91293030fae3e6e3a2e62622204"),
			hex!("4fe246f043fd62e33e819fc0a70b21a39edf528191b2e1570aeccd5a29b9b205"),
			hex!("50ee19ba6ae831f254eac14ac9bccce86834be1d82436f8e55984d78756d2031"),
			hex!("511e542a1d64c94bbfd79e28e2587b93dd1d2e4e1d531215e0b97ae8f168e51f"),
			hex!("527c138d69f6c0b3c8185fdc59b13e76c413bff31a7c4c86ae10fd1c0fc8eb97"),
			hex!("529c96d3ae3b6047ced8a01fa9c5ad6c111143e023b5bd5106b094e584ef1744"),
			hex!("5579bdd77dd40048002e1ef4fdd9f7f9d5f782283442cfad24c1e2979ccde069"),
			hex!("55d79ea6d9d4a9a8a4712428ab839ece13c2e16cf7d48fc8285e7b9171233f52"),
			hex!("56dc20413f5d004459dd4d0648114dd59678195132e101ab4227585a6b64b893"),
			hex!("571727abf1f2d55539ac993630c6ee4685f1b5de1ce648c4a645c95c757b950d"),
			hex!("571964d4216826071406e2d6249f97c574c3d3851e20486455efdecb9f0acc52"),
			hex!("5726020af78dea37e8457e31864468885704e7d7ba9e1020214ccac90d47f94d"),
			hex!("57bc453d3e4b3598339b010f304ded90cb11103eae57ad4ad579177108269767"),
			hex!("583342cd349a8cb1b8ffd5691d87809c13c40dcfc5b303eff4b39b528bbe58ae"),
			hex!("587497a7b26dce7193209505c86692103cd06e38626548f318700303f5176d72"),
			hex!("5885cb7afaf8b28fdd9f81045c57753e5323909832c463c00232c82e7b09b5cb"),
			hex!("595f92913bfa7fae7acfd19ae8e5a0cf1d96cf3d8bc1fc2833843c6ebec4355c"),
			hex!("5ab63820d12850c8bf4c07fa9e50cef26e220ac41c26a27f751533a4532a143e"),
			hex!("5b32b10ee7463c39f16cfd3dc7ed93f4d09fce6a8ad65c37b6af380eca5e7da2"),
			hex!("5ca5466a2fc8292a385796ee719f50a344a80bc903e7d8a24a554001c111ec13"),
			hex!("5cdfe3c2437155975a9b07ccbaf9242df94549c0431a7fdf55c848803e5e2973"),
			hex!("5cfd0fa36fe7b2c3302eae183089c1158e8672d13c68e333f803aa6c061c2bfb"),
			hex!("5dee6207ab81f635401b3537d74b4f47d4b7e5c84a39cd1b03edab185b1c71b0"),
			hex!("5e44f5d2bbfd0ede9f83e2cf3765207ea74860225deb230220aa2fc3db5c9d00"),
			hex!("5e9eec1012424f92a9a1678fc5062357438801e4c133c4e411055e0412cdcea3"),
			hex!("5eae1d837f37f3ac37dd17b8343be1d49783ad8e326e21c482abf9b863f8c862"),
			hex!("5eb36b60f0fc4b9177116eba3e5cd57fea6289a57f5f5b9ffeb0475c66e7a521"),
			hex!("61b297af7920a9cedf4e86f32a9e5d8a7602ac451829d7679e57a3f566b3cd5f"),
			hex!("628301071f75a8014d8eb73f6b9b7fc04436385395cf2848645f7bf828b4c72e"),
			hex!("63067133e0b9d601f3cc1301e7012d5f07f295c952fe4d5463e9ed2a5c10dfb6"),
			hex!("63dc02100d0c044c19f33597a97a9dc4f380121c47265be34289646f7534f02b"),
			hex!("64702eb70d3e15e4ca3154cc114e931750159fdc6c335fcb62e41f6fae7933c3"),
			hex!("6505c40d148dd38b8b431e29af6e27fff9b54a5b8503ea826dc4cf08fbd56a98"),
			hex!("655e047214bcb9017374fc20068ab6370588263610fb4d11ae1103b50535b58b"),
			hex!("66036ebe41433f58f929c3fd59508044e60cead5631a54a8975fd5538d0851fc"),
			hex!("676a468205c10d3550d7a198030aeeb3b6108ffa7fc025b58ee0d2b95cb6f36f"),
			hex!("676c144bb2a9d927f78a04bccffc73468fcfaff60232f6c9db7e688e30fc4cc0"),
			hex!("6b0f8ed55ec117ab0c4e05960dcd7a4187d51b9907c60f294f956a75c24a8cea"),
			hex!("6b64b6d26e69fe4f50f8cb13528b059f6709c20e568d5536a086f89e63899aca"),
			hex!("6b898a265f07867010402a3e0cc63cd48957e62d5e565df9d7c0360730857c5d"),
			hex!("6c5e1e64c0f337fbeef1e1777d76133cc3775175a441a24c7d9a1c0348eadd77"),
			hex!("6d3402787fcb101c2a0aa6d3e47beaa36e73c1823006da62b9aaf870490d6ad0"),
			hex!("6d862f22fe6b59499ded79e17ff67e1dddf7f1d24804a74d07781ed25e92cb56"),
			hex!("6e7bccf19b3c4cbb7ec881149ff3df5500b0c60228a76b9127cb2acfbd48f846"),
			hex!("6e880c3bb32af87bffd39f6bbe2f41fd3d42246133895d97405b425bc74e25ae"),
			hex!("6f701df9a0dd71dbd695f5f6430f309fc4dff38741fcde3ec8d40d805c9665f0"),
			hex!("6f767a59aca8c6995eb33eda2fbb4c554654ea05942f6a0fd26eb3b40c8c3fd4"),
			hex!("71f73679e5ac492e0948583ff375457a50f99cba1ca3e24b0a16da03fad06fea"),
			hex!("724a847f7abfb717b5b1ebd8bb08b51c365ddd7e87e1e4e4b45d76b9cb7f0468"),
			hex!("724e0db0fc0faf28f9d3ce6139ca458502a9e94c7b4fc878440a623ae101d875"),
			hex!("72c15799dfa2c72c764dba57125d6ac3e03376d997d6b2366e1fc07d16bd2eef"),
			hex!("7308ef54e2e0a75b5dfa496c43acd20f501caf3762b3a74853fdc2ad9846734d"),
			hex!("735c7fa8c6fc784b0aaafee900f3c975d0fc933aadc14040943a273e52c83edb"),
			hex!("73f20bf21277e7e8427fa5f8b356f045adfae6b75c9533f92ad80c2cb2d57dce"),
			hex!("74cd979006119b4a8c0f0bb5fa1c8d28883a81fc3f94d774e6edfb90765fe422"),
			hex!("76e3c88d4a7ab0ece91be0e6754150f51666519d20843bbd4a9a380ba78f1b06"),
			hex!("7851e0af960f4ebfbaf56fb9610ddfbebd4a7ab8f17849cb14eb9c1bfd9e1c99"),
			hex!("787e767b0f438a813ecc853f038018dd71f6f8fd12f81897986fba48362100e9"),
			hex!("7991d3c74a9b88cfa571d119bd72da2b48b2a15c4554d44be538b21c4569c797"),
			hex!("7a1a7315341d9721845e161556656fa49e30fbd0d2116287f4396cd69758f236"),
			hex!("7a3d12156961346f91989bb6ad38fb17b2fde21d47dd334781a604467d0e5899"),
			hex!("7b0c38ed8d551f87248e0ab09b9ccac40056abd28cbc2f163a43c6450d50611d"),
			hex!("7bf68fce04ffdc16625cc0eb63439f6bcf07f0fd6f4ea1fb7b7a2afd5b7b34ce"),
			hex!("7c14fb4369f79cd6c5b0151a54f8ade7d05e8e5c2d8a333a15cc69d62e1f1edf"),
			hex!("7ce574960f23c53d3d3c9a940152103a1756dbd43a76d72d1c6ed7c9850c7457"),
			hex!("7d0cec7858b2304f0afd05ad2b9193e0d63364979b41990f831cd94b12643e93"),
			hex!("7d46765b73915962ef87ca64d8fbbd7bf481b1594e671f221b7c566aa6719108"),
			hex!("7d6305a9c621403afe8061792b2beb05f57a0d118ad11934a44919c6855c2e7e"),
			hex!("7ddbebaf6c090283e0060876714557364786cb565f2405bfff827aa5938fbb2c"),
			hex!("7e02c30fb8f076347a6093e9283965fb89a6e3d1e2832c9e89c6d3072da9e679"),
			hex!("7e5da1f8d06bd05a22c85eb463bafad09fe2f84bb246f05c6c5d73b1c6406591"),
			hex!("7e7f71f99c55d7133cb6abcc7ceecbefd68a108b1787e6e1d3c38aa6bc0fedf1"),
			hex!("7f82fb34aca72915a1d85ff1e779d8909b33ded3d20ba406b6fcb184601e2fef"),
			hex!("801807bf9064ac6430a348a5829cf0b5b7d3054c3fbdcbe9913285adf6f2ca4d"),
			hex!("802579c2320e54c0fc38fce485db1d89eb9456fe7ffd326cd89142e33f0860d1"),
			hex!("80892cf2f2586286cb9d9599349983dda67efd7a9c984be04ff967c765fecdbe"),
			hex!("8154e55834d4c000822f3b9c3ccd9d8d86e2769ea02fd23a31fd66de83ec1fef"),
			hex!("83659f4e9167f0f8decc3ae3f11b790df720fc120f297148f4ae21faf8e40bd2"),
			hex!("83ac2a2e4e0b2c1a2fa79dbfa0841bf5f6cb7a4c308d076c79a200b429f5c52b"),
			hex!("85a5163d2fc99df3cf7a165aa11ed82b7d949d3fa493a0a502c21fe1381947f7"),
			hex!("87d885ca1d93b3b5e9681bab81ec133ab9c04a98610ab946c09117dfda8dae96"),
			hex!("880186e45243126507b4a93305852d861645a12af9bebad33d383230de6fbd3b"),
			hex!("88157424a27fdef14dbee0273d2683d1443521baa1cbdd2ba717892c912893a3"),
			hex!("89bfe34d8faed6417218c05fa388c9fc5f9f26db89d79baf7b9d1a1364ce0487"),
			hex!("8aee499770916ff6de861fc8fbb2c0be6c2164fa3833ba95d342f1f473032acb"),
			hex!("8e23780d67a8002e5c94282da1dfe3e4e5d70a7c67eb88e8bb0ee7a5e48cbf0b"),
			hex!("8f100cb93eb2142735f23391291cd1a72f2e4c24cd3739db739df095455f7da8"),
			hex!("8f5aab0507bc6bfb266adddbce2e2258fb1b6090e4034b96da77db05f2e2a3d1"),
			hex!("8fce62c8e5cf3d38204b70e588e4d8ede1025f98593616e45843c7ad1d58deae"),
			hex!("932f5a5c655f27e4bba5f82edc6914491aa028b4ec44310c340f248420bc3080"),
			hex!("936e4507f99679591ec362ca897451ddbee048e9dae9a1ab2c8fb5fcc6285cdd"),
			hex!("937ff12d7dcc1f94d73ac61d6ca51165ef6bfbac182f91c60f588dd1c7fe9500"),
			hex!("9602006ea88d2d9c2add5a9946caba5de7f6e543b58ac00f6908a1d51ae6ad02"),
			hex!("962644c31fb0abae3424596910be44014f66379a5b1f8636247485fc0c002b83"),
			hex!("97ae38e7e1b0f904fb93e7c3987d1b6c482d494af1b768515ffd7188e5d1bfbb"),
			hex!("98bda504923e4d4c148ef770ea0d0f65ca1f013758f37bcc609506b6f5461033"),
			hex!("9a5b54af7a2de83bbbbecd5fcf3dd325bddf861708d53519997399abfa3c3ad2"),
			hex!("9ad218d474345401d3df670bb661892a31351e8ef6bedc30f5378f7af8cdeda5"),
			hex!("9bc6f280eca830c87af2a16a0eaf6735c59e04cd03ec85f1a40f439263f65b66"),
			hex!("9d212c8034dace1e3610fc36456f782366e4d6e917d4f02676fee7db6ddde024"),
			hex!("9d985458767818b7849af9cfa539e0997e457e82563718f92b5aa4997789d0ab"),
			hex!("9de9385a95b35d9e41d3514a7124357de7c70abd835822a43720128c6e51cf31"),
			hex!("9f0482a1f6320f0849378bec18c2dc9b4082320dd9ee3a1cb85141f31fd3ec26"),
			hex!("a00954cdb7055e2a7cecbe225094c10655810d256b78fec639b349cc07a32dec"),
			hex!("a037f1c5d8d1a451eb38193d46eff999f5dff832078912f87cd79a194928baad"),
			hex!("a091c27bd60b4ce7022d2fa241dab8428d10624ec44b206f687d2ec0db367994"),
			hex!("a0c9c6efe8ca0cc3abc38a67b8514ce3f0b61fdc4ab6f4346af42d4e038d671c"),
			hex!("a28f0fb2d9ee46fcefd2a6ad405b8c42fb672274318d11a406d0c78412cf1aba"),
			hex!("a3b14f3584ccf1fbd358bda19c11062a7ae11d54fd32dfeb6b5110072ffc5383"),
			hex!("a453b2c3093cbc3e1d664164bb47031e22a61fb7e9fcc08bd0cb4d1167623685"),
			hex!("a59400d3dadb5708b3abc45602b6f71616c64ae878b65f6bf25710f5c42870d2"),
			hex!("a657601cc00b7e28fa2dbe7d3a331d4a7e1d28aeec5421d2ac6e1f1f591ad4eb"),
			hex!("a7a4281adfcac0b51e70fc4df0abdbbf5c75c119cd07c87b4b71e05fc4f98960"),
			hex!("a906998027ac32b9d1c082b7804d07d2ea57b4c053b85c08e607d9364c5e546e"),
			hex!("a9145bd8ddbe0f263f5dcb897cb524ea564c344eaa6a051401c66ceeeb50dabf"),
			hex!("a95f4afc1310f74cad3796d6531c420a750294be1e25780959680fb1234e31ee"),
			hex!("a9c0ce58624db9aba04d337f1c734efb95f75dd9ba3fe03d93254863e4f9647b"),
			hex!("a9fd5ec8a9cfea51e86e1fef5323077b6fb3678c6361488bcf5cb3cabd758a2e"),
			hex!("a9febbc2e4869ea9e8511413709670d17dfed17c5ec54143bd33558fd63d636a"),
			hex!("aa5e44bafe5c07cebfafaeed80e5fb2c15c573b48f90ad6aa83b266c705d17fe"),
			hex!("aa5f62c2c12cc58cea72dd9278ac06077311676a3e7df969f2316c6eecad6709"),
			hex!("aa9cb7a4ad812ef900cc5b9234d1ff7380701abbe8536b1133d2aa98885310fc"),
			hex!("ab76a4dc5c789f05ce7843d6dbd824f8fde7003ee4903eca3922f419ec120055"),
			hex!("ab79766923383acd4efcc7f9a6628cfde15c9b32e4fa7de85530172d4871bb1b"),
			hex!("ac675a9615c6a628e31c22d88ff29b19fb2f5f1883a94ef67e2251d25545b96b"),
			hex!("ac72a4cfdf2a62c70aacef75af71bd7c3aadcc6b31a3da4bf778dd0bc179e0f8"),
			hex!("aca8974b5ebf7c05440c31ddc2801efb18bf52aac17bd9d9ef36358b8e510a19"),
			hex!("ad05e704a9e9c4cbf68c837b38db3d1d444c9263792c7ebef81392f74f0ebcbb"),
			hex!("adeff2f6f22d23f6d20ca5276c0a9d68fcdb548ac7185a2294c70aa7c8d936e7"),
			hex!("b01340d55f1a383c3427a575ea5eea0aa2373eae8b31901a0af7cb730a9aadaa"),
			hex!("b04d9533423e321fb3d8d013e01d7635c40a22c7dd3cc5d317fb23e879151c26"),
			hex!("b05ab5e130da58ab46ed0a521f889bb0cd932b0c50235af8a915144bbaca796e"),
			hex!("b08d6e5c49153f678b98b10b9e52e737c97ad00ee3e20a067d0def842e633941"),
			hex!("b2d68768528171ee2ecbfddb53422f226854e62737a83c8725dd0c4196d51af2"),
			hex!("b3ed32656a0c68fdff46c96142b1fb3be48fedcb34c9c039fd25a7ee15687cbe"),
			hex!("b4073aed2c515a3ac133363c1f68c2a232c3a6201fcb07ea8831614e90c34d33"),
			hex!("b4a143c9a6f59020b2fee5f91c937511500523a2a2387160a0c88c61efcb8df2"),
			hex!("b5b3ea97d3d3ba042a20eb56a691b1b0fe77539711b97ab2b31ba07ef95d3a0a"),
			hex!("b6bbccfe9255006693b7b36bcec9f83d0ed7f065d9a4337c83807f793b0efdd7"),
			hex!("b70b241ae3785d6b28eef2157876cab2e5e1df5bf134c5db5530abbca1f6ff7c"),
			hex!("b7267daf1cd33ba28fd70ef54be13c28d05597173ed831106c00d538e3bce25c"),
			hex!("b7ccf22642d3908f4ae20b5e92711203f8c7cb1c563c604edb464ce366d9ecc3"),
			hex!("b7e6b7232b0ebbd6b858dd27b19b6f0095029ada1cac52f4ae105aedcdbe75ef"),
			hex!("b895240e4c63409e79a74f091fc3f55df19b0eaff0b80751ebe1a962292a4b7b"),
			hex!("b9d516528c0de12f32770726e4b3768b8c86708555d277be7e2715937662309a"),
			hex!("ba75c77d19690e7b921b6eb24a1d88b599c27e841fff84cb483ba9b9ff2df812"),
			hex!("ba85106a6bceca32e5870f7aed4bab6f861f73a5dcd1409c37f43064a6051b3e"),
			hex!("ba8dda9a84cf38074f945b359aaec261c70f6df6e1d5be4c89d570f28db218c3"),
			hex!("bb3becd854bfdb77622eb70d4b5f39b5f17a209b152c306ec29f6fe2b32cf2b8"),
			hex!("bba7ac775eb6db79c94e24fca20f709ad2ffb0387c85229a36e9f7acba53a3c9"),
			hex!("bbab9d892be432e3d7d4b0aa1b622473a684c661de1280f6346afdfa924d85e2"),
			hex!("bca57bbf5e735f508054cdd81c1bd1d93482446911cbc9e027311944736cade4"),
			hex!("bcac2fff970355ad73add6320dd61e30a4ba052cf43dec0794618e72b8fb4ff0"),
			hex!("bd362020a22986e8ca3e3462c4ea6756c6af9152bf7190b53f005d6b19359889"),
			hex!("bd3df977962755040997bfdb8d594103ee29c2fe5597adcc46c75cda48673f6d"),
			hex!("bddc37cf43b029e038b6bb7e46471cebb731748140278d9a850567201fc4131f"),
			hex!("be46b68e040ed5adde06018c5b1c6f802b82fb36d1ce09e85ef491923aa5d4e6"),
			hex!("be913d19d362e833d38c2f90e4fc7ec37d69ea323504badc41b852a18133219b"),
			hex!("bedf54accc69cad1ae6768d6946b6743cfd2df08f53c0a7e7e4757321929e7b5"),
			hex!("bf14f5b878640e60037d410c2cf550b360bb4c6c8deaa21c4695cc59bcf19a59"),
			hex!("c0b33e8010a00b1e918699fe1459ef52f6fbf7801c38b138ff9c0217364d169a"),
			hex!("c0e3952d5983ed8380fe3f88b198612509ba08c1566d3a1859ebc075b26d2af4"),
			hex!("c11e228eda5e81f6b0780a2cf93cc8cad66dc85735022580245ed3fdb1cad66e"),
			hex!("c306c084f9edfc974beb97126441c189a3046d754ff45ecf79abd3d75482efe7"),
			hex!("c3148b787f257cfc8cbce1e10bb1fa29d32b2df338f27ad67f2d25cbfe4ea863"),
			hex!("c389860e482b35554183b3c52ebf8f4378c7f9bb5e0b7ad4a1730b71367dc677"),
			hex!("c3c06b0a5fe8789f1f0af9ad6d61b9ddbc6c340ca45575fbf3eb34ac9a26a5c2"),
			hex!("c507598bc461eab884382e05e59cf375082a6b7a74c0a8081c8f728f7872bcc1"),
			hex!("c51802dac5f9d7ab0bb4bac8ab730b571c2314c31008263d20588b20852be909"),
			hex!("c5ba9d3aea5fc51cca420c0839761cb967cf7f3bfafc194d18468c9e21014e81"),
			hex!("c5bd9592a3f356df6be95819697e838dbc100f8f8d5d2da70612f80d505f7b30"),
			hex!("c5d05e0b245f1a74945a11c15f23730451bd4e2e94311dfae6af95c37c4d501b"),
			hex!("c65fda18c723cea3c8597be703fd90d5ea9f93570d6b40e44ed55b11c0b0563a"),
			hex!("c6845dc882290e84b8bd50c6f89a8f69bb5cb75749a91fb8262303ac6ee2d9f9"),
			hex!("c7396d89d11f0a34cfa06597bd4f779290d427d1146559e5e5f814a412136959"),
			hex!("c742dc425c660418f550a727ecf1e89151377160d724c83432d15cf05083f3fb"),
			hex!("c7cba4c11ff05adf8d78ee2b5dcc1c0a1d1c65419dbf1a4cc4dc5a41678cb285"),
			hex!("c93fb61d285aa9bf6b7828c45688cdc18ee47f4e4be2b755a7e5113c98daebe2"),
			hex!("c97843f1da287681cfadb638d2c36216eaf1fff230fe20b291bbca144a0536fc"),
			hex!("ca3ba4ac08ee6d634ff8d72d59c558953d9f29c914e7aa8b797e09904b443919"),
			hex!("ca82a6b9b5848c657cce8fbfa1b91dbef1ef7bd3376670f3de03708d75756204"),
			hex!("cad4a482be3ec1bd510c29bbcde5d5759ab8afafca2529fc5e675ed3f1af5a79"),
			hex!("cad9c169c1c62126d0894e86e9f134182b99435fd1e9757d021c29832b076646"),
			hex!("cb69182fe71b65d4cc689f5882de5dabee107167a540fb153afeb1a47c0c054e"),
			hex!("cc9c70374fad5dfb027feec79718782e5a2bb82fa2a400e4a426f59b349ad33c"),
			hex!("ccd07aa13473783cc5f1708a0e7d5e2e231d7da7ec5c7e16c06315ac18a7803e"),
			hex!("ccd16e861c1b51c75ce111830ec6e8c13ee1212ff9ac4c046ef96fa338116d2f"),
			hex!("ce13a473e75eb59d490c77bc81ed8f6a1d91dd267536fba53ddad4a4559dc201"),
			hex!("cecf11cf221bdb29dce8152be9dbc5a954510cd655609aed220a1cf23035e825"),
			hex!("cee76b8c26322f8e08a9104c5264025506bd470b212895f96ef05e62f4078d6c"),
			hex!("cee9ec948fe055d8b0ecf081c85483674f76e976e25cecbf39cb745008997880"),
			hex!("cf3592e0012ae721f2ce0137561ce3f5496320383cbf76d2c7f60016a4fd73f9"),
			hex!("cf98484287365ac9f12c5d8ffb43f1ddbc9d86b05214362aadbe5a42518e7a39"),
			hex!("d010730455a480e605572a6aab908f078952d0a9f8e63adb82a726a5c839a634"),
			hex!("d04f5c07709181a42284be32761d31b16d77f62425048df4cc4c3acd85f9b2ab"),
			hex!("d0dd615b60bcd27a44c7a5c7eb16a2c09c3e873c3a017bd214e67ce08df2b279"),
			hex!("d0f67c5bf148e7df9bae4edaab74a4826241089bf35ef75224f8dd9fe505bf30"),
			hex!("d13ea87f01cd8d8ab466865df55013e0ed724ab7daa299bc688589cd5d4e6c1c"),
			hex!("d26249f9f90fab275c699357be901def71eb2907383eea031a5e67c3b6c78eb5"),
			hex!("d296b8ea2cf235202ebeb4dbd0f6f71d9674bff1a5f28a506ffebc52b45cd18c"),
			hex!("d3060faf10feee3d831031c7a1d6980f4d2cecba7f1445b755379a845b49e3c8"),
			hex!("d426f0be2888aac1883d59a6e6e2abf6d720bd3c20166d3e2240dc8932c34460"),
			hex!("d4c251397eb79fb614bdc01c1cabffabb11a43b11c71e43e22227b112f9cff46"),
			hex!("d5b12a847c829cc2488e4cebbd1aa46e6cd7cd5765014492cb4b9bb50e453cd8"),
			hex!("d6e6cceef09138d491e58dacd2faf49c7aa9bd08bcd326907bf035e21c55bfa0"),
			hex!("d79149dbe962581b8a199d6c77afc8cc8b5518e4f955fc26d9b9359b28224fa8"),
			hex!("d90baab3c87cbb47d764a8e910cc0cad4a3f015ba11ecd36db5b63577769a561"),
			hex!("d90f09e0c208e85fe953e700e2078435902a4f3b21453259c4be89325c4af9eb"),
			hex!("d9b44bc3b417bf7e3962c4690ed197c3f3d7546767c6ea6ed6adf7e79f3f07af"),
			hex!("da93e7722349823df5e63bc88174f3c6b53aac9f64c08b3975abb7c32b48892f"),
			hex!("db5f731d6378700ac6b7f2ffb781f0c26ce6c411b304e252812d1ba29d729c7b"),
			hex!("dc6e18baea19b6e8a3299f841061cff9c817027228806f51d028ca28f61eeb84"),
			hex!("dd28d1d04b6f0e85d56077a9305781d754e9d8eed652c7905c5f74b111860d51"),
			hex!("dd852c82afb12059b5470f70f5e2ff0437246cd35483692fd16b7658f4cdeb8c"),
			hex!("ddd2cfd49289d10bfdbad42e45bb0bfe12d18f3f222f30bae0762f7726ac9d78"),
			hex!("de92bb50e1d70b0db7b339c4e07ba995efd70a8269da28b4ddfcdcb07e30f92f"),
			hex!("df06788069cef3fb6ccc7c6686811b35ae2d055a9c78b672b10b8ef764cf0141"),
			hex!("df230bb9e82a657c34b80a6ffb4ee61e4244f41009d923bf2a3310ed27b081d5"),
			hex!("df4fc837e8bb7a0883db06ab65900386b207ab38077e75d7d536e18fc970fe6f"),
			hex!("e00a01b779c9f3cc361e6bc94bf96a320720bbeeda2dc7e5b50e4b059df03408"),
			hex!("e3233ff3ca4f82df32e165ef4ddd99a160d20d791f22231020ad4ce994a539e0"),
			hex!("e365c1ae4d9b51f028bfb21cdfc7dfe74e2a3b009e69f32b3092e17414447271"),
			hex!("e389669a9472ba3a227cd36bbb240e53d544c1bb913623d388446b4af34d1faa"),
			hex!("e395aae790de1fed6b2c2301c545c87848986902127b02f25d83e4469d6e453f"),
			hex!("e3ac69c3ac776d7c7737e34111ca52de2fd17ea39160b382fa78471391b46264"),
			hex!("e3fbeafff3de1039a0ae4a24325a7514d50fea8926768eb937033ad86d32bd8a"),
			hex!("e46214635c0929e9d1445e1cf7ddcb4345105b74201e170f55ecb434a0b50924"),
			hex!("e50e9f313c96ac0908840bd854be8052a4e4361f40bc58085cde671ab187d6ec"),
			hex!("e600f853dc1e51cdf291ca217d180bf309589258ed5597a122b85b63a716d757"),
			hex!("e69baa3d0d403097b4b84c531443c9392e626c69c5d20ff519494c7fb445ee8c"),
			hex!("e720df848d1ba0ba401decafc27c8eb9239dd45e6e5aafe2e3f0f2d3f7e62839"),
			hex!("e8c7cbc1f07a909f91e9d82fae56e1a44fc26ee2dbca57fa58ddfb5d555ba51f"),
			hex!("e9e21aa455a6d171ece8c7ff0c1ba35a4d2ca9191f4dc442f9186cac702064af"),
			hex!("e9e5a66eb333735985eb4882da1ac87ce3d1242781623c83795cdb5ad4964e30"),
			hex!("eae25dcb14d57828c345d61e949c6662633cbefce70d2b74d319ae10613503bb"),
			hex!("ebe0913e831343ad36368acc328f4a9a3bbe1bb9987327bcac78d0f69fbea95f"),
			hex!("ec52c16fe78e60b6ad41ecccacae64f1e6610cc95ff60c9a63da7aca17332991"),
			hex!("ecc0ca4043011e40fabd9c5771aa71196dce2d8bf5cc12e4824223ac2ff5fef8"),
			hex!("ece04a17bf784981038ff79015a0dac37d50dcbbc5edc1b52c22679546583cb1"),
			hex!("ed292e651221e69c8a9227e1c6b6f1a377df7e8a7719d54160c8af1199d5539c"),
			hex!("ed6c3670bbf3472e4c33d5159a43d9f7afeb08fbf9bf744e3782cd55a9c3961e"),
			hex!("eda35b12f714d1dd5c43a61bcbf646f93ad22734caded4f25c0f571902ea2946"),
			hex!("edcf77c8332d6cd7dc55dfd0cd91411d9f8528d8e1e103ed4b0715bfdc08abee"),
			hex!("ee604dee03a5437b749556e674b96763a7d48dc91303f00d62ea7c5abd2a4702"),
			hex!("f0742044c6472bf4f5e30420a75be83632d5e8ef87ff878fb31d2ab27d5c60f1"),
			hex!("f35a3674ac332e727ff4a6deb6c56421650d08fdf988c86827cf88eda7feb036"),
			hex!("f49672b7054d772957d40de4237fa688dd908c224013b24fc226df9da9acf03a"),
			hex!("f538fc2ce556e155fa2013059aa627ffa37d694933491e316c44f19ea9334401"),
			hex!("f5c935a65edffbc6d2f10a97294750d97bb944daf2ecc82f3905378c0f7da605"),
			hex!("f6dade4ceedcba5239efba3a1bed7e361f1e6e248f9d7da967c6ece8dd891cc4"),
			hex!("f7d609169b59a8ffde1daec06124d656dfaf74d0a06be5f63b70e04553e20960"),
			hex!("f848b930858a35535340171a25a41f426c6b80c6efe102bf4b477b790fd63daf"),
			hex!("f8ed22f2aae410546561ef81059a53f7e331ce731bd46a3dca7c81577fb23b49"),
			hex!("f92002ca50e80d07031592a5426b1389c6199ac74e149d4b80d11f6b4e038105"),
			hex!("f93ff63bb01be4979dd492b98e81a9b690c776536a8a8eb38d0be8e141d787a6"),
			hex!("f958cfdcb1c3754dcd31ede43367acee4bdbf4b36a893db7502a1c1068651992"),
			hex!("fa66db3aad1f65716d055901ed4318e6e106c6623c934e6eab21bec5fb9e197f"),
			hex!("fd90085bce33fc765f20dce173b1de98000315587a300b5e32dfb5cce4500c2b"),
			hex!("fdc281a44139a1d786cc8c0c5e1f49fea75fffeed3f6cbc7202705459fe6e343"),
			hex!("ffdc0d411b62aed4d7c4bfbcb8df724711de6549a4b5fa16676ab7ff04ef8dd0"),
			// Key in active validator set (as of block 21543445).
			// Uncomment to verify the migration will error when it detects an undecodable key
			// hex!("ffd31bf694e0d28434da06abd3fe4febe23b25054b5de48ed94246339c51b2e6"),
		];

		impl frame_support::traits::OnRuntimeUpgrade for Migration {
			fn on_runtime_upgrade() -> Weight {
				use sp_std::collections::btree_set::BTreeSet;

				let validators_with_undecodable_entries = KEYS.into_iter().collect::<BTreeSet<_>>();
				let active_validators = pallet_session::Validators::<Runtime>::get();

				for v in active_validators {
					log::info!("Active Validator Key {:?}", array_bytes::bytes2hex("0x", &v));
					if validators_with_undecodable_entries.contains::<[u8; 32]>(&v.clone().into()) {
						panic!(
							"Validator Key {:?} has undecodable entries",
							array_bytes::bytes2hex("0x", &v)
						);
					}
				}

				RocksDbWeight::get().reads(0)
			}
		}
	}

	/// Unreleased migrations. Add new ones here:
	pub type Unreleased = (
		check_session_keys::Migration,
		pallet_staking::migrations::v14::MigrateToV14<Runtime>,
		parachains_configuration::migration::v10::MigrateToV10<Runtime>,
		pallet_grandpa::migrations::MigrateV4ToV5<Runtime>,
		pallet_nomination_pools::migration::versioned::V5toV6<Runtime>,
		// TODO:(PR#137) - replace with fixed/released version
		crate::test_oliverfix_migration::V6ToV7<Runtime>,
		// pallet_nomination_pools::migration::versioned::V6ToV7<Runtime>,
		// TODO:(PR#137) - replace with fixed/released version
		crate::test_oliverfix_migration::V7ToV8<Runtime>,
		// pallet_nomination_pools::migration::versioned::V7ToV8<Runtime>,
	);
}

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
	Migrations,
>;
/// The payload being signed in the transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

#[cfg(feature = "runtime-benchmarks")]
mod benches {
	frame_benchmarking::define_benchmarks!(
		// Polkadot
		// NOTE: Make sure to prefix these with `runtime_common::` so
		// that the path resolves correctly in the generated file.
		[runtime_common::auctions, Auctions]
		[runtime_common::crowdloan, Crowdloan]
		[runtime_common::claims, Claims]
		[runtime_common::slots, Slots]
		[runtime_common::paras_registrar, Registrar]
		[runtime_parachains::configuration, Configuration]
		[runtime_parachains::hrmp, Hrmp]
		[runtime_parachains::disputes, ParasDisputes]
		[runtime_parachains::disputes::slashing, ParasSlashing]
		[runtime_parachains::inclusion, ParaInclusion]
		[runtime_parachains::initializer, Initializer]
		[runtime_parachains::paras_inherent, ParaInherent]
		[runtime_parachains::paras, Paras]
		// Substrate
		[pallet_balances, Native]
		[pallet_balances, Nis]
		[pallet_bags_list, VoterList]
		[frame_benchmarking::baseline, Baseline::<Runtime>]
		[pallet_bounties, Bounties]
		[pallet_child_bounties, ChildBounties]
		[pallet_conviction_voting, ConvictionVoting]
		[pallet_election_provider_multi_phase, ElectionProviderMultiPhase]
		[frame_election_provider_support, ElectionProviderBench::<Runtime>]
		[pallet_fast_unstake, FastUnstake]
		[pallet_nis, Nis]
		[pallet_identity, Identity]
		[pallet_im_online, ImOnline]
		[pallet_indices, Indices]
		[pallet_message_queue, MessageQueue]
		[pallet_multisig, Multisig]
		[pallet_nomination_pools, NominationPoolsBench::<Runtime>]
		[pallet_offences, OffencesBench::<Runtime>]
		[pallet_preimage, Preimage]
		[pallet_proxy, Proxy]
		[pallet_ranked_collective, FellowshipCollective]
		[pallet_recovery, Recovery]
		[pallet_referenda, Referenda]
		[pallet_referenda, FellowshipReferenda]
		[pallet_scheduler, Scheduler]
		[pallet_session, SessionBench::<Runtime>]
		[pallet_society, Society]
		[pallet_staking, Staking]
		[frame_system, SystemBench::<Runtime>]
		[pallet_timestamp, Timestamp]
		[pallet_treasury, Treasury]
		[pallet_utility, Utility]
		[pallet_vesting, Vesting]
		[pallet_whitelist, Whitelist]
		[pallet_asset_rate, AssetRate]
		// XCM
		[pallet_xcm, PalletXcmExtrinsiscsBenchmark::<Runtime>]
		[pallet_xcm_benchmarks::fungible, pallet_xcm_benchmarks::fungible::Pallet::<Runtime>]
		[pallet_xcm_benchmarks::generic, pallet_xcm_benchmarks::generic::Pallet::<Runtime>]
	);
}

sp_api::impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block);
		}

		fn initialize_block(header: &<Block as BlockT>::Header) {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> sp_std::vec::Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl block_builder_api::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: Block,
			data: inherents::InherentData,
		) -> inherents::CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl tx_pool_api::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl offchain_primitives::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	#[api_version(7)]
	impl primitives::runtime_api::ParachainHost<Block> for Runtime {
		fn validators() -> Vec<ValidatorId> {
			parachains_runtime_api_impl::validators::<Runtime>()
		}

		fn validator_groups() -> (Vec<Vec<ValidatorIndex>>, GroupRotationInfo<BlockNumber>) {
			parachains_runtime_api_impl::validator_groups::<Runtime>()
		}

		fn availability_cores() -> Vec<CoreState<Hash, BlockNumber>> {
			parachains_runtime_api_impl::availability_cores::<Runtime>()
		}

		fn persisted_validation_data(para_id: ParaId, assumption: OccupiedCoreAssumption)
			-> Option<PersistedValidationData<Hash, BlockNumber>> {
			parachains_runtime_api_impl::persisted_validation_data::<Runtime>(para_id, assumption)
		}

		fn assumed_validation_data(
			para_id: ParaId,
			expected_persisted_validation_data_hash: Hash,
		) -> Option<(PersistedValidationData<Hash, BlockNumber>, ValidationCodeHash)> {
			parachains_runtime_api_impl::assumed_validation_data::<Runtime>(
				para_id,
				expected_persisted_validation_data_hash,
			)
		}

		fn check_validation_outputs(
			para_id: ParaId,
			outputs: primitives::CandidateCommitments,
		) -> bool {
			parachains_runtime_api_impl::check_validation_outputs::<Runtime>(para_id, outputs)
		}

		fn session_index_for_child() -> SessionIndex {
			parachains_runtime_api_impl::session_index_for_child::<Runtime>()
		}

		fn validation_code(para_id: ParaId, assumption: OccupiedCoreAssumption)
			-> Option<ValidationCode> {
			parachains_runtime_api_impl::validation_code::<Runtime>(para_id, assumption)
		}

		fn candidate_pending_availability(para_id: ParaId) -> Option<CommittedCandidateReceipt<Hash>> {
			parachains_runtime_api_impl::candidate_pending_availability::<Runtime>(para_id)
		}

		fn candidate_events() -> Vec<CandidateEvent<Hash>> {
			parachains_runtime_api_impl::candidate_events::<Runtime, _>(|ev| {
				match ev {
					RuntimeEvent::ParaInclusion(ev) => {
						Some(ev)
					}
					_ => None,
				}
			})
		}

		fn session_info(index: SessionIndex) -> Option<SessionInfo> {
			parachains_runtime_api_impl::session_info::<Runtime>(index)
		}

		fn session_executor_params(session_index: SessionIndex) -> Option<ExecutorParams> {
			parachains_runtime_api_impl::session_executor_params::<Runtime>(session_index)
		}

		fn dmq_contents(recipient: ParaId) -> Vec<InboundDownwardMessage<BlockNumber>> {
			parachains_runtime_api_impl::dmq_contents::<Runtime>(recipient)
		}

		fn inbound_hrmp_channels_contents(
			recipient: ParaId
		) -> BTreeMap<ParaId, Vec<InboundHrmpMessage<BlockNumber>>> {
			parachains_runtime_api_impl::inbound_hrmp_channels_contents::<Runtime>(recipient)
		}

		fn validation_code_by_hash(hash: ValidationCodeHash) -> Option<ValidationCode> {
			parachains_runtime_api_impl::validation_code_by_hash::<Runtime>(hash)
		}

		fn on_chain_votes() -> Option<ScrapedOnChainVotes<Hash>> {
			parachains_runtime_api_impl::on_chain_votes::<Runtime>()
		}

		fn submit_pvf_check_statement(
			stmt: primitives::PvfCheckStatement,
			signature: primitives::ValidatorSignature,
		) {
			parachains_runtime_api_impl::submit_pvf_check_statement::<Runtime>(stmt, signature)
		}

		fn pvfs_require_precheck() -> Vec<ValidationCodeHash> {
			parachains_runtime_api_impl::pvfs_require_precheck::<Runtime>()
		}

		fn validation_code_hash(para_id: ParaId, assumption: OccupiedCoreAssumption)
			-> Option<ValidationCodeHash>
		{
			parachains_runtime_api_impl::validation_code_hash::<Runtime>(para_id, assumption)
		}

		fn disputes() -> Vec<(SessionIndex, CandidateHash, DisputeState<BlockNumber>)> {
			parachains_runtime_api_impl::get_session_disputes::<Runtime>()
		}

		fn unapplied_slashes(
		) -> Vec<(SessionIndex, CandidateHash, slashing::PendingSlashes)> {
			parachains_runtime_api_impl::unapplied_slashes::<Runtime>()
		}

		fn key_ownership_proof(
			validator_id: ValidatorId,
		) -> Option<slashing::OpaqueKeyOwnershipProof> {
			use parity_scale_codec::Encode;

			Historical::prove((PARACHAIN_KEY_TYPE_ID, validator_id))
				.map(|p| p.encode())
				.map(slashing::OpaqueKeyOwnershipProof::new)
		}

		fn submit_report_dispute_lost(
			dispute_proof: slashing::DisputeProof,
			key_ownership_proof: slashing::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			parachains_runtime_api_impl::submit_unsigned_slashing_report::<Runtime>(
				dispute_proof,
				key_ownership_proof,
			)
		}

		fn minimum_backing_votes() -> u32 {
			parachains_runtime_api_impl::minimum_backing_votes::<Runtime>()
		}

		fn para_backing_state(para_id: ParaId) -> Option<primitives::async_backing::BackingState> {
			parachains_runtime_api_impl::backing_state::<Runtime>(para_id)
		}

		fn async_backing_params() -> primitives::AsyncBackingParams {
			parachains_runtime_api_impl::async_backing_params::<Runtime>()
		}
	}

	impl beefy_primitives::BeefyApi<Block, BeefyId> for Runtime {
		fn beefy_genesis() -> Option<BlockNumber> {
			Beefy::genesis_block()
		}

		fn validator_set() -> Option<beefy_primitives::ValidatorSet<BeefyId>> {
			Beefy::validator_set()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			equivocation_proof: beefy_primitives::EquivocationProof<
				BlockNumber,
				BeefyId,
				BeefySignature,
			>,
			key_owner_proof: beefy_primitives::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;

			Beefy::submit_unsigned_equivocation_report(
				equivocation_proof,
				key_owner_proof,
			)
		}

		fn generate_key_ownership_proof(
			_set_id: beefy_primitives::ValidatorSetId,
			authority_id: BeefyId,
		) -> Option<beefy_primitives::OpaqueKeyOwnershipProof> {
			use parity_scale_codec::Encode;

			Historical::prove((beefy_primitives::KEY_TYPE, authority_id))
				.map(|p| p.encode())
				.map(beefy_primitives::OpaqueKeyOwnershipProof::new)
		}
	}

	impl mmr::MmrApi<Block, Hash, BlockNumber> for Runtime {
		fn mmr_root() -> Result<mmr::Hash, mmr::Error> {
			Ok(Mmr::mmr_root())
		}

		fn mmr_leaf_count() -> Result<mmr::LeafIndex, mmr::Error> {
			Ok(Mmr::mmr_leaves())
		}

		fn generate_proof(
			block_numbers: Vec<BlockNumber>,
			best_known_block_number: Option<BlockNumber>,
		) -> Result<(Vec<mmr::EncodableOpaqueLeaf>, mmr::Proof<mmr::Hash>), mmr::Error> {
			Mmr::generate_proof(block_numbers, best_known_block_number).map(
				|(leaves, proof)| {
					(
						leaves
							.into_iter()
							.map(|leaf| mmr::EncodableOpaqueLeaf::from_leaf(&leaf))
							.collect(),
						proof,
					)
				},
			)
		}

		fn verify_proof(leaves: Vec<mmr::EncodableOpaqueLeaf>, proof: mmr::Proof<mmr::Hash>)
			-> Result<(), mmr::Error>
		{
			let leaves = leaves.into_iter().map(|leaf|
				leaf.into_opaque_leaf()
				.try_decode()
				.ok_or(mmr::Error::Verify)).collect::<Result<Vec<mmr::Leaf>, mmr::Error>>()?;
			Mmr::verify_leaves(leaves, proof)
		}

		fn verify_proof_stateless(
			root: mmr::Hash,
			leaves: Vec<mmr::EncodableOpaqueLeaf>,
			proof: mmr::Proof<mmr::Hash>
		) -> Result<(), mmr::Error> {
			let nodes = leaves.into_iter().map(|leaf|mmr::DataOrHash::Data(leaf.into_opaque_leaf())).collect();
			pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(root, nodes, proof)
		}
	}

	impl pallet_beefy_mmr::BeefyMmrApi<Block, Hash> for RuntimeApi {
		fn authority_set_proof() -> beefy_primitives::mmr::BeefyAuthoritySet<Hash> {
			BeefyMmrLeaf::authority_set_proof()
		}

		fn next_authority_set_proof() -> beefy_primitives::mmr::BeefyNextAuthoritySet<Hash> {
			BeefyMmrLeaf::next_authority_set_proof()
		}
	}

	impl fg_primitives::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> Vec<(GrandpaId, u64)> {
			Grandpa::grandpa_authorities()
		}

		fn current_set_id() -> fg_primitives::SetId {
			Grandpa::current_set_id()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			equivocation_proof: fg_primitives::EquivocationProof<
				<Block as BlockT>::Hash,
				sp_runtime::traits::NumberFor<Block>,
			>,
			key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;

			Grandpa::submit_unsigned_equivocation_report(
				equivocation_proof,
				key_owner_proof,
			)
		}

		fn generate_key_ownership_proof(
			_set_id: fg_primitives::SetId,
			authority_id: fg_primitives::AuthorityId,
		) -> Option<fg_primitives::OpaqueKeyOwnershipProof> {
			use parity_scale_codec::Encode;

			Historical::prove((fg_primitives::KEY_TYPE, authority_id))
				.map(|p| p.encode())
				.map(fg_primitives::OpaqueKeyOwnershipProof::new)
		}
	}

	impl babe_primitives::BabeApi<Block> for Runtime {
		fn configuration() -> babe_primitives::BabeConfiguration {
			let epoch_config = Babe::epoch_config().unwrap_or(BABE_GENESIS_EPOCH_CONFIG);
			babe_primitives::BabeConfiguration {
				slot_duration: Babe::slot_duration(),
				epoch_length: EpochDuration::get(),
				c: epoch_config.c,
				authorities: Babe::authorities().to_vec(),
				randomness: Babe::randomness(),
				allowed_slots: epoch_config.allowed_slots,
			}
		}

		fn current_epoch_start() -> babe_primitives::Slot {
			Babe::current_epoch_start()
		}

		fn current_epoch() -> babe_primitives::Epoch {
			Babe::current_epoch()
		}

		fn next_epoch() -> babe_primitives::Epoch {
			Babe::next_epoch()
		}

		fn generate_key_ownership_proof(
			_slot: babe_primitives::Slot,
			authority_id: babe_primitives::AuthorityId,
		) -> Option<babe_primitives::OpaqueKeyOwnershipProof> {
			use parity_scale_codec::Encode;

			Historical::prove((babe_primitives::KEY_TYPE, authority_id))
				.map(|p| p.encode())
				.map(babe_primitives::OpaqueKeyOwnershipProof::new)
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			equivocation_proof: babe_primitives::EquivocationProof<<Block as BlockT>::Header>,
			key_owner_proof: babe_primitives::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;

			Babe::submit_unsigned_equivocation_report(
				equivocation_proof,
				key_owner_proof,
			)
		}
	}

	impl authority_discovery_primitives::AuthorityDiscoveryApi<Block> for Runtime {
		fn authorities() -> Vec<AuthorityDiscoveryId> {
			parachains_runtime_api_impl::relevant_authority_ids::<Runtime>()
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			SessionKeys::generate(seed)
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
			SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		Balance,
	> for Runtime {
		fn query_info(uxt: <Block as BlockT>::Extrinsic, len: u32) -> RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(uxt: <Block as BlockT>::Extrinsic, len: u32) -> FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}
		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentCallApi<Block, Balance, RuntimeCall>
		for Runtime
	{
		fn query_call_info(call: RuntimeCall, len: u32) -> RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_call_info(call, len)
		}
		fn query_call_fee_details(call: RuntimeCall, len: u32) -> FeeDetails<Balance> {
			TransactionPayment::query_call_fee_details(call, len)
		}
		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}
		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl pallet_nomination_pools_runtime_api::NominationPoolsApi<
		Block,
		AccountId,
		Balance,
	> for Runtime {
		fn pending_rewards(member: AccountId) -> Balance {
			NominationPools::api_pending_rewards(member).unwrap_or_default()
		}

		fn points_to_balance(pool_id: pallet_nomination_pools::PoolId, points: Balance) -> Balance {
			NominationPools::api_points_to_balance(pool_id, points)
		}

		fn balance_to_points(pool_id: pallet_nomination_pools::PoolId, new_funds: Balance) -> Balance {
			NominationPools::api_balance_to_points(pool_id, new_funds)
		}
	}

	impl pallet_staking_runtime_api::StakingApi<Block, Balance, AccountId> for Runtime {
		fn nominations_quota(balance: Balance) -> u32 {
			Staking::api_nominations_quota(balance)
		}

		fn eras_stakers_page_count(era: sp_staking::EraIndex, account: AccountId) -> sp_staking::Page {
			Staking::api_eras_stakers_page_count(era, account)
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn create_default_config() -> Vec<u8> {
			create_default_config::<RuntimeGenesisConfig>()
		}

		fn build_config(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_config::<RuntimeGenesisConfig>(config)
		}
	}

	#[cfg(feature = "try-runtime")]
	impl frame_try_runtime::TryRuntime<Block> for Runtime {
		fn on_runtime_upgrade(checks: frame_try_runtime::UpgradeCheckSelect) -> (Weight, Weight) {
			log::info!("try-runtime::on_runtime_upgrade kusama.");
			let weight = Executive::try_runtime_upgrade(checks).unwrap();
			(weight, BlockWeights::get().max_block)
		}

		fn execute_block(
			block: Block,
			state_root_check: bool,
			signature_check: bool,
			select: frame_try_runtime::TryStateSelect,
		) -> Weight {
			// NOTE: intentional unwrap: we don't want to propagate the error backwards, and want to
			// have a backtrace here.
			Executive::try_execute_block(block, state_root_check, signature_check, select).unwrap()
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			use frame_benchmarking::{Benchmarking, BenchmarkList};
			use frame_support::traits::StorageInfoTrait;

			use pallet_session_benchmarking::Pallet as SessionBench;
			use pallet_offences_benchmarking::Pallet as OffencesBench;
			use pallet_election_provider_support_benchmarking::Pallet as ElectionProviderBench;
			use pallet_xcm::benchmarking::Pallet as PalletXcmExtrinsiscsBenchmark;
			use frame_system_benchmarking::Pallet as SystemBench;
			use pallet_nomination_pools_benchmarking::Pallet as NominationPoolsBench;
			use frame_benchmarking::baseline::Pallet as Baseline;

			// Benchmark files generated for `Balances/NisCounterpartBalances` instances are by default
			// `pallet_balances_balances.rs / pallet_balances_nis_counterpart_balances`, which is not really nice,
			// so with this redefinition we can change names to nicer:
			// `pallet_balances_native.rs / pallet_balances_nis.rs`.
			type Native = pallet_balances::Pallet::<Runtime, ()>;
			type Nis = pallet_balances::Pallet::<Runtime, NisCounterpartInstance>;

			let mut list = Vec::<BenchmarkList>::new();
			list_benchmarks!(list, extra);

			let storage_info = AllPalletsWithSystem::storage_info();
			return (list, storage_info)
		}

		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig
		) -> Result<
			Vec<frame_benchmarking::BenchmarkBatch>,
			sp_runtime::RuntimeString,
		> {
			use frame_support::traits::WhitelistedStorageKeys;
			use frame_benchmarking::{Benchmarking, BenchmarkBatch, BenchmarkError};
			use sp_storage::TrackedStorageKey;
			// Trying to add benchmarks directly to some pallets caused cyclic dependency issues.
			// To get around that, we separated the benchmarks into its own crate.
			use pallet_session_benchmarking::Pallet as SessionBench;
			use pallet_offences_benchmarking::Pallet as OffencesBench;
			use pallet_election_provider_support_benchmarking::Pallet as ElectionProviderBench;
			use frame_system_benchmarking::Pallet as SystemBench;
			use pallet_nomination_pools_benchmarking::Pallet as NominationPoolsBench;
			use frame_benchmarking::baseline::Pallet as Baseline;
			use xcm::latest::prelude::*;
			use xcm_config::{
				LocalCheckAccount, SovereignAccountOf, AssetHubLocation, TokenLocation, XcmConfig,
			};

			impl pallet_session_benchmarking::Config for Runtime {}
			impl pallet_offences_benchmarking::Config for Runtime {}
			impl pallet_election_provider_support_benchmarking::Config for Runtime {}
			impl frame_system_benchmarking::Config for Runtime {}
			impl frame_benchmarking::baseline::Config for Runtime {}
			impl pallet_nomination_pools_benchmarking::Config for Runtime {}
			impl runtime_parachains::disputes::slashing::benchmarking::Config for Runtime {}

			use pallet_xcm::benchmarking::Pallet as PalletXcmExtrinsiscsBenchmark;
			impl pallet_xcm::benchmarking::Config for Runtime {
				fn reachable_dest() -> Option<MultiLocation> {
					Some(crate::xcm_config::AssetHubLocation::get())
				}

				fn teleportable_asset_and_dest() -> Option<(MultiAsset, MultiLocation)> {
					// Relay/native token can be teleported to/from AH.
					Some((
						MultiAsset { fun: Fungible(EXISTENTIAL_DEPOSIT), id: Concrete(Here.into()) },
						crate::xcm_config::AssetHubLocation::get(),
					))
				}

				fn reserve_transferable_asset_and_dest() -> Option<(MultiAsset, MultiLocation)> {
					// Relay can reserve transfer native token to some random parachain.
					Some((
						MultiAsset {
							fun: Fungible(EXISTENTIAL_DEPOSIT),
							id: Concrete(Here.into())
						},
						crate::Junction::Parachain(43211234).into(),
					))
				}

				fn set_up_complex_asset_transfer(
				) -> Option<(MultiAssets, u32, MultiLocation, Box<dyn FnOnce()>)> {
					// Relay supports only native token, either reserve transfer it to non-system parachains,
					// or teleport it to system parachain. Use the teleport case for benchmarking as it's
					// slightly heavier.
					// Relay/native token can be teleported to/from AH.
					let native_location = Here.into();
					let dest = crate::xcm_config::AssetHubLocation::get();
					pallet_xcm::benchmarking::helpers::native_teleport_as_asset_transfer::<Runtime>(
						native_location,
						dest
					)
				}
			}

			parameter_types! {
				pub ExistentialDepositMultiAsset: Option<MultiAsset> = Some((
					TokenLocation::get(),
					ExistentialDeposit::get()
				).into());
				pub ToParachain: ParaId = kusama_runtime_constants::system_parachain::ASSET_HUB_ID.into();
			}

			impl pallet_xcm_benchmarks::Config for Runtime {
				type XcmConfig = XcmConfig;
				type AccountIdConverter = SovereignAccountOf;
				type DeliveryHelper = runtime_common::xcm_sender::ToParachainDeliveryHelper<
					XcmConfig,
					ExistentialDepositMultiAsset,
					xcm_config::PriceForChildParachainDelivery,
					ToParachain,
					(),
				>;
				fn valid_destination() -> Result<MultiLocation, BenchmarkError> {
					Ok(AssetHubLocation::get())
				}
				fn worst_case_holding(_depositable_count: u32) -> MultiAssets {
					// Kusama only knows about KSM.
					vec![MultiAsset{
						id: Concrete(TokenLocation::get()),
						fun: Fungible(1_000_000 * UNITS),
					}].into()
				}
			}

			parameter_types! {
				pub const TrustedTeleporter: Option<(MultiLocation, MultiAsset)> = Some((
					AssetHubLocation::get(),
					MultiAsset { fun: Fungible(1 * UNITS), id: Concrete(TokenLocation::get()) },
				));
				pub const TrustedReserve: Option<(MultiLocation, MultiAsset)> = None;
			}

			impl pallet_xcm_benchmarks::fungible::Config for Runtime {
				type TransactAsset = Balances;

				type CheckedAccount = LocalCheckAccount;
				type TrustedTeleporter = TrustedTeleporter;
				type TrustedReserve = TrustedReserve;

				fn get_multi_asset() -> MultiAsset {
					MultiAsset {
						id: Concrete(TokenLocation::get()),
						fun: Fungible(1 * UNITS),
					}
				}
			}

			impl pallet_xcm_benchmarks::generic::Config for Runtime {
				type TransactAsset = Balances;
				type RuntimeCall = RuntimeCall;

				fn worst_case_response() -> (u64, Response) {
					(0u64, Response::Version(Default::default()))
				}

				fn worst_case_asset_exchange() -> Result<(MultiAssets, MultiAssets), BenchmarkError> {
					// Kusama doesn't support asset exchanges
					Err(BenchmarkError::Skip)
				}

				fn universal_alias() -> Result<(MultiLocation, Junction), BenchmarkError> {
					// The XCM executor of Kusama doesn't have a configured `UniversalAliases`
					Err(BenchmarkError::Skip)
				}

				fn transact_origin_and_runtime_call() -> Result<(MultiLocation, RuntimeCall), BenchmarkError> {
					Ok((AssetHubLocation::get(), frame_system::Call::remark_with_event { remark: vec![] }.into()))
				}

				fn subscribe_origin() -> Result<MultiLocation, BenchmarkError> {
					Ok(AssetHubLocation::get())
				}

				fn claimable_asset() -> Result<(MultiLocation, MultiLocation, MultiAssets), BenchmarkError> {
					let origin = AssetHubLocation::get();
					let assets: MultiAssets = (Concrete(TokenLocation::get()), 1_000 * UNITS).into();
					let ticket = MultiLocation { parents: 0, interior: Here };
					Ok((origin, ticket, assets))
				}

				fn unlockable_asset() -> Result<(MultiLocation, MultiLocation, MultiAsset), BenchmarkError> {
					// Kusama doesn't support asset locking
					Err(BenchmarkError::Skip)
				}

				fn export_message_origin_and_destination(
				) -> Result<(MultiLocation, NetworkId, InteriorMultiLocation), BenchmarkError> {
					// Kusama doesn't support exporting messages
					Err(BenchmarkError::Skip)
				}

				fn alias_origin() -> Result<(MultiLocation, MultiLocation), BenchmarkError> {
					// The XCM executor of Kusama doesn't have a configured `Aliasers`
					Err(BenchmarkError::Skip)
				}
			}

			type Native = pallet_balances::Pallet::<Runtime, ()>;
			type Nis = pallet_balances::Pallet::<Runtime, NisCounterpartInstance>;

			let mut whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();
			let treasury_key = frame_system::Account::<Runtime>::hashed_key_for(Treasury::account_id());
			whitelist.push(treasury_key.to_vec().into());

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);

			add_benchmarks!(params, batches);

			Ok(batches)
		}
	}
}

#[cfg(test)]
mod fees_tests {
	use super::*;
	use sp_runtime::assert_eq_error_rate;

	#[test]
	fn signed_deposit_is_sensible() {
		// ensure this number does not change, or that it is checked after each change.
		// a 1 MB solution should need around 0.16 KSM deposit
		let deposit = SignedFixedDeposit::get() + (SignedDepositByte::get() * 1024 * 1024);
		assert_eq_error_rate!(deposit, UNITS * 167 / 100, UNITS / 100);
	}
}

#[cfg(test)]
mod multiplier_tests {
	use super::*;
	use frame_support::{
		dispatch::DispatchInfo,
		traits::{OnFinalize, PalletInfoAccess},
	};
	use runtime_common::{MinimumMultiplier, TargetBlockFullness};
	use separator::Separatable;
	use sp_runtime::traits::Convert;

	fn run_with_system_weight<F>(w: Weight, mut assertions: F)
	where
		F: FnMut() -> (),
	{
		let mut t: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
			.build_storage()
			.unwrap()
			.into();
		t.execute_with(|| {
			System::set_block_consumed_resources(w, 0);
			assertions()
		});
	}

	#[test]
	fn multiplier_can_grow_from_zero() {
		let minimum_multiplier = MinimumMultiplier::get();
		let target = TargetBlockFullness::get() *
			BlockWeights::get().get(DispatchClass::Normal).max_total.unwrap();
		// if the min is too small, then this will not change, and we are doomed forever.
		// the weight is 1/100th bigger than target.
		run_with_system_weight(target.saturating_mul(101) / 100, || {
			let next = SlowAdjustingFeeUpdate::<Runtime>::convert(minimum_multiplier);
			assert!(next > minimum_multiplier, "{:?} !>= {:?}", next, minimum_multiplier);
		})
	}

	#[test]
	fn fast_unstake_estimate() {
		use pallet_fast_unstake::WeightInfo;
		let block_time = BlockWeights::get().max_block.ref_time() as f32;
		let on_idle = weights::pallet_fast_unstake::WeightInfo::<Runtime>::on_idle_check(
			1000,
			<Runtime as pallet_fast_unstake::Config>::BatchSize::get(),
		)
		.ref_time() as f32;
		println!("ratio of block weight for full batch fast-unstake {}", on_idle / block_time);
		assert!(on_idle / block_time <= 0.5f32)
	}

	#[test]
	fn treasury_pallet_index_is_correct() {
		assert_eq!(TREASURY_PALLET_ID, <Treasury as PalletInfoAccess>::index() as u8);
	}

	#[test]
	#[ignore]
	fn multiplier_growth_simulator() {
		// assume the multiplier is initially set to its minimum. We update it with values twice the
		//target (target is 25%, thus 50%) and we see at which point it reaches 1.
		let mut multiplier = MinimumMultiplier::get();
		let block_weight = BlockWeights::get().get(DispatchClass::Normal).max_total.unwrap();
		let mut blocks = 0;
		let mut fees_paid = 0;

		frame_system::Pallet::<Runtime>::set_block_consumed_resources(Weight::MAX, 0);
		let info = DispatchInfo { weight: Weight::MAX, ..Default::default() };

		let mut t: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
			.build_storage()
			.unwrap()
			.into();
		// set the minimum
		t.execute_with(|| {
			pallet_transaction_payment::NextFeeMultiplier::<Runtime>::set(MinimumMultiplier::get());
		});

		while multiplier <= Multiplier::from_u32(1) {
			t.execute_with(|| {
				// imagine this tx was called.
				let fee = TransactionPayment::compute_fee(0, &info, 0);
				fees_paid += fee;

				// this will update the multiplier.
				System::set_block_consumed_resources(block_weight, 0);
				TransactionPayment::on_finalize(1);
				let next = TransactionPayment::next_fee_multiplier();

				assert!(next > multiplier, "{:?} !>= {:?}", next, multiplier);
				multiplier = next;

				println!(
					"block = {} / multiplier {:?} / fee = {:?} / fess so far {:?}",
					blocks,
					multiplier,
					fee.separated_string(),
					fees_paid.separated_string()
				);
			});
			blocks += 1;
		}
	}

	#[test]
	#[ignore]
	fn multiplier_cool_down_simulator() {
		// assume the multiplier is initially set to its minimum. We update it with values twice the
		//target (target is 25%, thus 50%) and we see at which point it reaches 1.
		let mut multiplier = Multiplier::from_u32(2);
		let mut blocks = 0;

		let mut t: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
			.build_storage()
			.unwrap()
			.into();
		// set the minimum
		t.execute_with(|| {
			pallet_transaction_payment::NextFeeMultiplier::<Runtime>::set(multiplier);
		});

		while multiplier > Multiplier::from_u32(0) {
			t.execute_with(|| {
				// this will update the multiplier.
				TransactionPayment::on_finalize(1);
				let next = TransactionPayment::next_fee_multiplier();

				assert!(next < multiplier, "{:?} !>= {:?}", next, multiplier);
				multiplier = next;

				println!("block = {} / multiplier {:?}", blocks, multiplier);
			});
			blocks += 1;
		}
	}
}

#[cfg(all(test, feature = "try-runtime"))]
mod remote_tests {
	use super::*;
	use frame_try_runtime::{runtime_decl_for_try_runtime::TryRuntime, UpgradeCheckSelect};
	use remote_externalities::{
		Builder, Mode, OfflineConfig, OnlineConfig, SnapshotConfig, Transport,
	};
	use std::env::var;

	#[tokio::test]
	async fn run_migrations() {
		if var("RUN_MIGRATION_TESTS").is_err() {
			return
		}

		sp_tracing::try_init_simple();
		let transport: Transport =
			var("WS").unwrap_or("wss://kusama-rpc.polkadot.io:443".to_string()).into();
		let maybe_state_snapshot: Option<SnapshotConfig> = var("SNAP").map(|s| s.into()).ok();
		let mut ext = Builder::<Block>::default()
			.mode(if let Some(state_snapshot) = maybe_state_snapshot {
				Mode::OfflineOrElseOnline(
					OfflineConfig { state_snapshot: state_snapshot.clone() },
					OnlineConfig {
						transport,
						state_snapshot: Some(state_snapshot),
						..Default::default()
					},
				)
			} else {
				Mode::Online(OnlineConfig { transport, ..Default::default() })
			})
			.build()
			.await
			.unwrap();
		ext.execute_with(|| Runtime::on_runtime_upgrade(UpgradeCheckSelect::PreAndPost));
	}

	#[tokio::test]
	#[ignore = "this test is meant to be executed manually"]
	async fn try_fast_unstake_all() {
		sp_tracing::try_init_simple();
		let transport: Transport =
			var("WS").unwrap_or("wss://kusama-rpc.polkadot.io:443".to_string()).into();
		let maybe_state_snapshot: Option<SnapshotConfig> = var("SNAP").map(|s| s.into()).ok();
		let mut ext = Builder::<Block>::default()
			.mode(if let Some(state_snapshot) = maybe_state_snapshot {
				Mode::OfflineOrElseOnline(
					OfflineConfig { state_snapshot: state_snapshot.clone() },
					OnlineConfig {
						transport,
						state_snapshot: Some(state_snapshot),
						..Default::default()
					},
				)
			} else {
				Mode::Online(OnlineConfig { transport, ..Default::default() })
			})
			.build()
			.await
			.unwrap();
		ext.execute_with(|| {
			pallet_fast_unstake::ErasToCheckPerBlock::<Runtime>::put(1);
			runtime_common::try_runtime::migrate_all_inactive_nominators::<Runtime>()
		});
	}
}

mod init_state_migration {
	use super::Runtime;
	use frame_support::traits::OnRuntimeUpgrade;
	use pallet_state_trie_migration::{AutoLimits, MigrationLimits, MigrationProcess};
	#[cfg(not(feature = "std"))]
	use sp_std::prelude::*;

	/// Initialize an automatic migration process.
	pub struct InitMigrate;
	impl OnRuntimeUpgrade for InitMigrate {
		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::DispatchError> {
			use parity_scale_codec::Encode;
			let migration_should_start = AutoLimits::<Runtime>::get().is_none() &&
				MigrationProcess::<Runtime>::get() == Default::default();
			Ok(migration_should_start.encode())
		}

		fn on_runtime_upgrade() -> frame_support::weights::Weight {
			if AutoLimits::<Runtime>::get().is_some() {
				log::warn!("Automatic trie migration already started, not proceeding.");
				return <Runtime as frame_system::Config>::DbWeight::get().reads(1)
			};

			if MigrationProcess::<Runtime>::get() != Default::default() {
				log::warn!("MigrationProcess is not Default. Not proceeding.");
				return <Runtime as frame_system::Config>::DbWeight::get().reads(2)
			};

			// Migration is not already running and `MigraitonProcess` is Default. Ready to run
			// migrations.
			//
			// We use limits to target 600ko proofs per block and
			// avg 800_000_000_000 of weight per block.
			// See spreadsheet 4800_400 in
			// https://raw.githubusercontent.com/cheme/substrate/try-runtime-mig/ksm.ods
			AutoLimits::<Runtime>::put(Some(MigrationLimits { item: 4_800, size: 204800 * 2 }));
			log::info!("Automatic trie migration started.");
			<Runtime as frame_system::Config>::DbWeight::get().reads_writes(2, 1)
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(
			migration_should_start_bytes: Vec<u8>,
		) -> Result<(), sp_runtime::DispatchError> {
			use parity_scale_codec::Decode;
			let migration_should_start: bool =
				Decode::decode(&mut migration_should_start_bytes.as_slice())
					.expect("failed to decode migration should start");

			if migration_should_start {
				frame_support::ensure!(
					AutoLimits::<Runtime>::get().is_some(),
					sp_runtime::DispatchError::Other("Automigration did not start as expected.")
				);
			}

			Ok(())
		}
	}
}

// TODO:(PR#137) - replace with fixed/released version
mod test_oliverfix_migration {
	use super::*;
	use frame_support::{
		traits::OnRuntimeUpgrade, DebugNoBound, RuntimeDebugNoBound, Twox64Concat,
	};
	use frame_system::pallet_prelude::BlockNumberFor;
	use pallet_nomination_pools::*;
	use sp_runtime::Saturating;

	pub type V7ToV8<T> = frame_support::migrations::VersionedMigration<
		7,
		8,
		v8::VersionUncheckedMigrateV7ToV8<T>,
		pallet_nomination_pools::pallet::Pallet<T>,
		<T as frame_system::Config>::DbWeight,
	>;

	pub type V6ToV7<T> = frame_support::migrations::VersionedMigration<
		6,
		7,
		v7::VersionUncheckedMigrateV6ToV7<T>,
		pallet_nomination_pools::pallet::Pallet<T>,
		<T as frame_system::Config>::DbWeight,
	>;

	pub mod v8 {
		use super::*;

		use super::v7::BondedPoolInner as OldBondedPoolInner;

		impl<T: Config> OldBondedPoolInner<T> {
			fn migrate_to_v8(self) -> BondedPoolInner<T> {
				BondedPoolInner {
					commission: Commission {
						current: self.commission.current,
						max: self.commission.max,
						change_rate: self.commission.change_rate,
						throttle_from: self.commission.throttle_from,
						// `claim_permission` is a new field.
						claim_permission: None,
					},
					member_counter: self.member_counter,
					points: self.points,
					roles: self.roles,
					state: self.state,
				}
			}
		}

		pub struct VersionUncheckedMigrateV7ToV8<T>(sp_std::marker::PhantomData<T>);

		impl<T: Config> OnRuntimeUpgrade for VersionUncheckedMigrateV7ToV8<T> {
			#[cfg(feature = "try-runtime")]
			fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
				Ok(Vec::new())
			}

			fn on_runtime_upgrade() -> Weight {
				let mut translated = 0u64;
				BondedPools::<T>::translate::<OldBondedPoolInner<T>, _>(|_key, old_value| {
					translated.saturating_inc();
					Some(old_value.migrate_to_v8())
				});
				T::DbWeight::get().reads_writes(translated, translated + 1)
			}

			#[cfg(feature = "try-runtime")]
			fn post_upgrade(_: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
				// Check new `claim_permission` field is present.
				frame_support::ensure!(
					BondedPools::<T>::iter()
						.all(|(_, inner)| inner.commission.claim_permission.is_none()),
					"`claim_permission` value has not been set correctly."
				);
				Ok(())
			}
		}
	}

	mod v7 {
		use super::*;

		use sp_staking::StakingInterface;
		// use frame_support::traits::GetStorageVersion;

		#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, DebugNoBound, PartialEq, Clone)]
		#[codec(mel_bound(T: Config))]
		#[scale_info(skip_type_params(T))]
		pub struct Commission<T: Config> {
			pub current: Option<(Perbill, T::AccountId)>,
			pub max: Option<Perbill>,
			pub change_rate: Option<CommissionChangeRate<BlockNumberFor<T>>>,
			pub throttle_from: Option<BlockNumberFor<T>>,
		}

		#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, DebugNoBound, PartialEq, Clone)]
		#[codec(mel_bound(T: Config))]
		#[scale_info(skip_type_params(T))]
		pub struct BondedPoolInner<T: Config> {
			pub commission: Commission<T>,
			pub member_counter: u32,
			pub points: BalanceOf<T>,
			pub roles: PoolRoles<T::AccountId>,
			pub state: PoolState,
		}

		#[derive(RuntimeDebugNoBound)]
		#[cfg_attr(feature = "std", derive(Clone, PartialEq))]
		pub struct BondedPool<T: Config> {
			/// The identifier of the pool.
			id: PoolId,
			/// The inner fields.
			inner: BondedPoolInner<T>,
		}

		impl<T: Config> BondedPool<T> {
			fn bonded_account(&self) -> T::AccountId {
				Pallet::<T>::create_bonded_account(self.id)
			}
		}

		#[frame_support::storage_alias]
		pub type BondedPools<T: Config> =
			CountedStorageMap<Pallet<T>, Twox64Concat, PoolId, BondedPoolInner<T>>;

		pub struct VersionUncheckedMigrateV6ToV7<T>(sp_std::marker::PhantomData<T>);
		impl<T: Config> VersionUncheckedMigrateV6ToV7<T> {
			fn calculate_tvl_by_total_stake() -> BalanceOf<T> {
				BondedPools::<T>::iter()
					.map(|(id, inner)| {
						T::Staking::total_stake(
							&BondedPool { id, inner: inner.clone() }.bonded_account(),
						)
						.unwrap_or_default()
					})
					.reduce(|acc, total_balance| acc + total_balance)
					.unwrap_or_default()
			}
		}

		impl<T: Config> OnRuntimeUpgrade for VersionUncheckedMigrateV6ToV7<T> {
			fn on_runtime_upgrade() -> Weight {
				let migrated = BondedPools::<T>::count();
				// The TVL should be the sum of all the funds that are actively staked and in the
				// unbonding process of the account of each pool.
				let tvl: BalanceOf<T> = Self::calculate_tvl_by_total_stake();

				TotalValueLocked::<T>::set(tvl);

				log!(info, "Upgraded {} pools with a TVL of {:?}", migrated, tvl);

				// reads: migrated * (BondedPools +  Staking::total_stake) + count + onchain
				// version
				//
				// writes: current version + TVL
				T::DbWeight::get()
					.reads_writes(migrated.saturating_mul(2).saturating_add(2).into(), 2)
			}

			#[cfg(feature = "try-runtime")]
			fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
				Ok(Vec::new())
			}

			#[cfg(feature = "try-runtime")]
			fn post_upgrade(_data: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
				// check that the `TotalValueLocked` written is actually the sum of `total_stake` of
				// the `BondedPools``
				let tvl: BalanceOf<T> = Self::calculate_tvl_by_total_stake();
				frame_support::ensure!(
					TotalValueLocked::<T>::get() == tvl,
					"TVL written is not equal to `Staking::total_stake` of all `BondedPools`."
				);

				// TODO: skip for now
				// calculate the sum of `total_balance` of all `PoolMember` as the upper bound for
				// the `TotalValueLocked`.
				// let total_balance_members: BalanceOf<T> = PoolMembers::<T>::iter()
				// 	.map(|(_, member)| member.total_balance())
				// 	.reduce(|acc, total_balance| acc + total_balance)
				// 	.unwrap_or_default();
				//
				// frame_support::ensure!(
				// 	TotalValueLocked::<T>::get() <= total_balance_members,
				// 	"TVL is greater than the balance of all PoolMembers."
				// );
				//
				// frame_support::ensure!(
				// 	Pallet::<T>::on_chain_storage_version() >= 7,
				// 	"nomination-pools::migration::v7: wrong storage version"
				// );

				Ok(())
			}
		}
	}
}
