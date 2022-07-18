use std::env;
use std::fs::File;
use std::ops::Not;
use std::str::FromStr;
use std::string::String;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::{prelude::*, types::Address, utils::keccak256};
use ethers_flashbots::*;
use ethers_providers::Ws;
use log::Level::Debug;
use log::{debug, info, log_enabled};
use ron::de::from_reader;
use serde::Deserialize;
use url::Url;

// Mainnet ENS contract addresses
// TODO(Derive these by chain rather than hard code)
pub(crate) const ENS_BASE_REGISTRAR: &str = "0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85";
pub(crate) const ETH_REGISTRAR_CONTROLLER: &str = "0x283af0b28c62c092c9727f1ee09c02ca627eb7f5";

// Generate the type-safe contract bindings by providing the ABI
// definition in json.
abigen!(
    ENSBaseRegistrar,
    "./src/abi/ens_base_registrar.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    ETHRegistrarController,
    "./src/abi/eth_registrar_controller.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

/// Whether we want to simulate + send or just simulate transactions on the relay
#[derive(Debug, Copy, Clone)]
pub enum OperationMode {
    Send,
    Simulate,
}

/// Whether we want to work on mainnet or goerli
#[derive(Debug, Copy, Clone)]
pub enum Chain {
    Mainnet,
    Goerli,
}

/// Information about an ENS Registration to process.
#[derive(Debug, Deserialize)]
pub struct Registration {
    pub wei_price: U256,
    pub ens: String,
    pub owner: Option<Address>,
    pub expiration: Option<U256>,
}

/// Runtime configuration details for the bot.
pub struct Config {
    pub executor_pk: String,
    pub flashbots_pk: String,
    pub ws_rpc: String,
    pub chain: Chain,
    pub operation_mode: OperationMode,
    pub registrations_file: String,
}

/// Implementation for config
/// The config is read from shell environment variables.
impl Config {
    pub fn new() -> Result<Config> {
        let ws_rpc = env::var("ETH_RPC_WS").context("Set the ETH_RPC_WS environment variable.")?;
        let executor_pk = env::var("PRIVATE_KEY")
            .context("Set the PRIVATE_KEY environment variable.")?[2..]
            .to_string();
        let flashbots_pk = env::var("FLASHBOTS_KEY")
            .context("Set the FLASHBOTS_KEY environment variable.")?[2..]
            .to_string();
        let operation_mode = env::var("SIMULATE_ONLY");
        let operation_mode = match operation_mode {
            Err(_) => OperationMode::Send,
            Ok(_) => {
                info!("Running in simulation only mode.");
                OperationMode::Simulate
            }
        };
        let chain = env::var("TESTNET");
        let chain = match chain {
            Err(_) => {
                info!("Running on Mainnet.");
                Chain::Mainnet
            }
            Ok(_) => {
                info!("Running on Goerli testnet.");
                Chain::Goerli
            }
        };
        let registrations_file = env::var("REGISTRATIONS_FILE")
            .context("Set the REGISTRATIONS_FILE environment variable")?;
        Ok(Config {
            executor_pk,
            flashbots_pk,
            ws_rpc,
            chain,
            operation_mode,
            registrations_file,
        })
    }
}

/// ENS Registration sniper bot
struct RegistrationSniper {
    operation_mode: OperationMode,
    provider: Arc<Provider<Ws>>,
    wallet: LocalWallet,
    client: Arc<SignerMiddleware<FlashbotsMiddleware<Arc<Provider<Ws>>, LocalWallet>, LocalWallet>>,
    eth_registrar_controller: ETHRegistrarController<
        ethers::prelude::SignerMiddleware<
            FlashbotsMiddleware<Arc<Provider<Ws>>, LocalWallet>,
            LocalWallet,
        >,
    >,
    base_registrar: ENSBaseRegistrar<
        ethers::prelude::SignerMiddleware<
            FlashbotsMiddleware<Arc<Provider<Ws>>, LocalWallet>,
            LocalWallet,
        >,
    >,
    registrations: Vec<Registration>,
    min_commitment_age: U256,
    min_registration_duration: U256,
    grace_period: U256,
}

/// Implementation of ENS registration sniper bot.
impl RegistrationSniper {
    /// Returns a new bot.
    pub async fn new(config: &Config) -> Result<RegistrationSniper> {
        // Setup a websocket connection to geth client.
        let operation_mode = config.operation_mode;
        let ws = Ws::connect(&config.ws_rpc).await?;
        let provider = Provider::new(ws).interval(Duration::from_millis(500));
        let provider = Arc::new(provider);

        // Setup wallet
        let mut wallet: LocalWallet =
            LocalWallet::from_str(&*config.executor_pk).context("Invalid private key")?;

        // Flashbots signer wallet
        let mut flashbots_wallet: LocalWallet =
            LocalWallet::from_str(&config.flashbots_pk).context("Invalid flashbots key")?;

        // TODO(Eventually, we'll want to point at our own mev-geth for simulations)
        // this will keep our signing key score up if that becomes an issue in landing
        // bundles.

        // Switch for goerli testnet or mainnet

        let relay;
        match config.chain {
            Chain::Mainnet => {
                relay = "https://relay.flashbots.net";
                flashbots_wallet = flashbots_wallet.with_chain_id(1u64);
                wallet = wallet.with_chain_id(1u64);
            }
            Chain::Goerli => {
                flashbots_wallet = flashbots_wallet.with_chain_id(5u64);
                wallet = wallet.with_chain_id(5u64);
                relay = "https://relay-goerli.flashbots.net";
            }
        }

        // TODO(Consider another middleware for direct submission to ethermine)
        // Setup the flashbots middleware
        let flashbots_middleware: FlashbotsMiddleware<Arc<Provider<Ws>>, LocalWallet> =
            FlashbotsMiddleware::new(
                provider.clone(),
                Url::parse(relay)?,
                flashbots_wallet.clone(),
            );

        // Setup Ethereum client with flashbots middleware
        let client: SignerMiddleware<
            FlashbotsMiddleware<Arc<Provider<Ws>>, LocalWallet>,
            LocalWallet,
        > = SignerMiddleware::new(flashbots_middleware, wallet.clone());
        let client: Arc<
            SignerMiddleware<FlashbotsMiddleware<Arc<Provider<Ws>>, LocalWallet>, LocalWallet>,
        > = Arc::new(client);

        // Setup the ENS base registrar
        let base_registrar_address: Address = ENS_BASE_REGISTRAR.parse().unwrap();
        let base_registrar = ENSBaseRegistrar::new(base_registrar_address, client.clone());

        // Setup the ETH registrar controller
        let eth_registrar_controller_address: Address = ETH_REGISTRAR_CONTROLLER.parse().unwrap();
        let eth_registrar_controller =
            ETHRegistrarController::new(eth_registrar_controller_address, client.clone());

        let grace_period = base_registrar.grace_period().call().await?;

        let registrations = RegistrationSniper::load_registrations(&config.registrations_file)?;

        let min_commitment_age = eth_registrar_controller.min_commitment_age().call().await?;

        let min_registration_duration = eth_registrar_controller
            .min_registration_duration()
            .call()
            .await?;

        Ok(RegistrationSniper {
            operation_mode,
            provider,
            wallet,
            client,
            eth_registrar_controller,
            base_registrar,
            registrations,
            min_commitment_age,
            min_registration_duration,
            grace_period,
        })
    }

    /// Return a new flashbots bundle request for this block
    async fn new_bundle_request(&self) -> Result<BundleRequest> {
        let block = self.client.get_block_number().await?;
        let mut bundle = BundleRequest::new();
        // We can simulate against state data from the last mined block.
        bundle = bundle.set_simulation_block(block);
        // We want to target the pending block.
        bundle = bundle.set_block(block + 1);
        let now = SystemTime::now();
        bundle = bundle.set_simulation_timestamp(now.duration_since(UNIX_EPOCH)?.as_secs());
        Ok(bundle)
    }

    async fn process_bundle_request(&self, bundle: BundleRequest) -> Result<()> {
        dbg!(bundle.transactions());
        if bundle.transactions().is_empty().not() {
            match self.operation_mode {
                OperationMode::Send => {
                    // First Simulate
                    let simulated_bundle = self.client.inner().simulate_bundle(&bundle);
                    match simulated_bundle.await {
                        Ok(res) => debug!("Simulated bundle: {:?}", res),
                        Err(e) => debug!("Bundle simulation failed: {}", e),
                    }
                    // Then send
                    let pending_bundle = self.client.inner().send_bundle(&bundle).await?;
                    match pending_bundle.await {
                        Ok(bundle_hash) => println!(
                            "Bundle with hash {:?} was included in target block",
                            bundle_hash
                        ),
                        Err(PendingBundleError::BundleNotIncluded) => {
                            println!("Bundle was not included in target block.")
                        }
                        Err(_) => println!("An unknown error occured."),
                    }
                }
                OperationMode::Simulate => {
                    let simulated_bundle = self.client.inner().simulate_bundle(&bundle);
                    match simulated_bundle.await {
                        Ok(res) => debug!("Simulated bundle: {:?}", res),
                        Err(e) => debug!("Bundle simulation failed: {}", e),
                    }
                }
            }
        }
        Ok(())
    }

    /// Load desired registrations to snipe from file
    fn load_registrations(registrations_file: &str) -> Result<Vec<Registration>> {
        // Read registrations from file
        info!("Loading registrations");
        let f = File::open(registrations_file).context("Failed opening registrations file")?;
        match from_reader(f) {
            Ok(x) => Ok(x),
            Err(e) => {
                panic!("Failed to load config: {}", e);
            }
        }
    }

    /// Return boolean result of if domain is valid.
    async fn valid(&self, registration: &Registration) -> Result<bool> {
        let valid = self
            .eth_registrar_controller
            .valid(registration.ens.clone())
            .call()
            .await?;
        Ok(valid)
    }

    async fn available(&self, registration: &Registration) -> Result<bool> {
        let available = self
            .eth_registrar_controller
            .available(registration.ens.clone())
            .call()
            .await?;
        Ok(available)
    }

    /// Return boolean result of iff domain is valid and available at timestamp now or in the future.
    async fn available_at(&self, registration: &Registration, timestamp: U256) -> Result<bool> {
        // TODO(Account for timestamps in the past?)
        // If there is no expiration, then it's available already
        let expiration = match registration.expiration {
            Some(e) => e,
            None => return Ok(true),
        };
        // If there is an expiration, then we need to account for the grace period
        Ok((expiration + self.grace_period) < timestamp)
    }

    /// Return rent price in wei for minimum duration.
    async fn rent_price(&self, registration: &Registration) -> Result<U256> {
        // TODO(Consider)
        // "Because the rent price may vary over time, callers are recommended to send slightly
        // more than the value returned by rentPrice - a premium of 5-10% will likely be
        // sufficient. Any excess funds are returned to the caller." - from ENS docs
        // Would add gas cost and make bot 10% less gas efficient, not doing for now.
        let rent_price = self
            .eth_registrar_controller
            .rent_price(registration.ens.clone(), self.min_registration_duration)
            .call()
            .await?;
        Ok(rent_price)
    }

    /// Return a salt to use in the commit.
    fn commit_salt() -> [u8; 32] {
        // FIXME(Generate a more secure salt/secret here)
        [
            b'k', b'o', b'd', b'e', b'x', b'm', b'e', b'v', b'a', b'l', b'p', b'h', b'a', b'n',
            b'o', b'l', b'e', b'a', b'k', b'a', b'l', b'p', b'h', b'a', b'p', b'l', b's', b't',
            b'h', b'a', b'n', b'k',
        ]
    }

    /// Calculate the commitment hash and return it.
    async fn commit_hash(&self, registration: &Registration) -> Result<[u8; 32]> {
        let commit_hash: [u8; 32] = self
            .eth_registrar_controller
            .make_commitment(
                registration.ens.clone(),
                self.wallet.address(),
                RegistrationSniper::commit_salt(),
            )
            .call()
            .await?;
        Ok(commit_hash)
    }

    /// Returns 0 if not committed, else the unix timestamp of the commitment.
    async fn committed(&self, commit_hash: &[u8; 32]) -> Result<U256> {
        let committed = self
            .eth_registrar_controller
            .commitments(*commit_hash)
            .call()
            .await?;
        Ok(committed)
    }

    /// Return the present owner of the registration.
    async fn owner(&self, registration: &Registration) -> Result<Option<H160>> {
        // Domains in the legacy registrar will not return an owner
        let owner = match self
            .base_registrar
            .owner_of(U256::from(keccak256(&registration.ens)))
            .call()
            .await
        {
            Err(_) => None,
            Ok(x) => Some(x),
        };
        Ok(owner)
    }

    /// Return the expiration timestamp of the registration as U256.
    async fn expiration(&self, registration: &Registration) -> Result<Option<U256>> {
        let expiration: Option<U256> = Some(
            self.base_registrar
                .name_expires(U256::from(keccak256(&registration.ens)))
                .call()
                .await?,
        );
        Ok(expiration)
    }

    async fn update_all_registrations(&mut self) -> Result<()> {
        // TODO(Async updates concurrently)

        // Holder for data
        let mut updated_info: Vec<(Option<H160>, Option<U256>)> = vec![];

        // Update the info about each registration.
        for registration in self.registrations.iter() {
            let mut owner: Option<H160> = None;
            let mut expiration: Option<U256> = None;
            if !self.available(registration).await? {
                owner = self.owner(registration).await?;
                expiration = self.expiration(registration).await?;
            }
            updated_info.push((owner, expiration));
        }
        // Working around an immutable borrow of a mutably borrowed self.
        for (pos, registration) in self.registrations.iter_mut().enumerate() {
            registration.owner = updated_info[pos].0;
            registration.expiration = updated_info[pos].1;
        }

        // Print all registration info if we are in debug mode
        if log_enabled!(Debug) {
            debug!("Registration info:");
            dbg!("{}", &self.registrations);
        }
        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        // General theory here is to calculate all time for 1 block from now, as we are targeting
        // one block ahead.
        // So, this represents that unit of time offset.
        let block_time = U256::from(15u64);

        // Do initial update of registrations
        self.update_all_registrations().await?;

        // Get stream of blocks.
        let mut block_stream = self.provider.watch_blocks().await?;

        // For each block...
        while block_stream.next().await.is_some() {
            // For each block:
            info!(
                "Got block: {}",
                self.provider
                    .get_block(BlockNumber::Latest)
                    .await
                    .unwrap()
                    .unwrap()
                    .number
                    .unwrap()
            );

            // Prepare an empty bundle request
            let mut bundle_request = self.new_bundle_request().await?;

            // Get the nonce for the wallet
            let mut nonce = self
                .client
                .get_transaction_count(
                    self.wallet.address(),
                    Some(BlockId::from(BlockNumber::Latest)),
                )
                .await?;

            // This is the base fee for the block.
            let base_fee = self.provider.get_gas_price().await?;

            // For each registration...
            // TODO(concurrent loop here)
            'domains: for registration in self.registrations.iter() {
                // Calculate the ENS cost to register for the shortest duration.
                let registration_cost = self.rent_price(registration).await?;

                // Let's make sure our bid will cover the registration.
                if registration_cost >= registration.wei_price {
                    continue 'domains;
                }

                // Get the present timestamp
                let now = U256::from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());

                // TODO(Account for gas fluctuations between blocks with a mutable variable)

                // The max gas is 350,000 for commit + register
                let gas_price = (registration.wei_price - registration_cost) / U256::from(350000);

                // No reason to continue if our bid won't pay basefee.
                if base_fee >= gas_price {
                    continue 'domains;
                }

                // TODO(Clerical: remove domains already sniped to save loops)
                // Check if we own the registration
                let mut register = false;
                match registration.owner {
                    Some(owner) => {
                        if owner != self.wallet.address() {
                            register = true;
                        }
                    }
                    _ => register = true,
                }

                // TODO(Refactor the tx formation, signature, addition to bundle to a related func)
                // If we don't own it, let's register.
                // TODO(Calculate the exact timestamp this will be available, and then register up
                // to 15s in advance)
                if register
                    && self.valid(registration).await?
                    && self.available_at(registration, now + block_time).await?
                {
                    let commit_hash = self.commit_hash(registration).await?;
                    let committed = self.committed(&commit_hash).await?;
                    // TODO(Check that we have enough eth, attempting to deduct for each reg)
                    // if we aren't committed yet
                    if committed == U256::zero() {
                        // Commit
                        let tx = {
                            let mut call = self
                                .eth_registrar_controller
                                .method::<_, H256>("commit", commit_hash)?;
                            call.tx.set_nonce(nonce);
                            // Allow a little padding - uses 46,267 gas
                            call.tx.set_gas(U256::from(50000));
                            call.tx.set_gas_price(gas_price);
                            let inner: TypedTransaction = call.tx;
                            // If we wanted to assert here on failure we could do this:
                            // self.client.fill_transaction(&mut inner, None).await?;
                            inner
                        };
                        let signature = self.client.signer().sign_transaction(&tx).await?;
                        bundle_request = bundle_request.push_transaction(
                            tx.rlp_signed(self.client.signer().chain_id(), &signature),
                        );
                        nonce += U256::one();
                    }
                    // if we already committed
                    else {
                        // Check commit age
                        let commit_age = now - committed;
                        // If the commit is old enough, let's register.
                        // In fact, let's try to register 1 block early, even if it'll revert.
                        if commit_age >= (self.min_commitment_age - block_time) {
                            let tx = {
                                let mut call =
                                    self.eth_registrar_controller
                                        .method::<_, (String, H160, U256, H256)>(
                                            "register",
                                            (
                                                registration.ens.clone(),
                                                self.wallet.address(),
                                                self.min_registration_duration,
                                                RegistrationSniper::commit_salt(),
                                            ),
                                        )?;
                                call.tx.set_nonce(nonce);
                                call.tx.set_value(registration_cost);
                                // Allow a little padding - uses ~261,940 gas
                                call.tx.set_gas(U256::from(300000));
                                call.tx.set_gas_price(gas_price);
                                let inner: TypedTransaction = call.tx;
                                // If we wanted to assert here on failure we could do this:
                                // self.client.fill_transaction(&mut inner, None).await?;
                                inner
                            };
                            let signature = self.client.signer().sign_transaction(&tx).await?;
                            bundle_request = bundle_request.push_transaction(
                                tx.rlp_signed(self.client.signer().chain_id(), &signature),
                            );
                            nonce += U256::one();
                        }
                    }
                }
            }
            self.process_bundle_request(bundle_request).await?;
        }

        Ok(())
    }
}

// This is wrapped up in a thread pool for call by the binary.
#[tokio::main]
pub async fn run(config: &Config) -> Result<()> {
    // Setup the sniper
    let mut registration_sniper = RegistrationSniper::new(config).await?;

    // Run the sniper
    registration_sniper.run().await?;

    // Exit cleanly
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::RegistrationSniper;

    #[test]
    fn test_load_registrations() {
        if RegistrationSniper::load_registrations("test_data/ens_registrations.ron").is_ok() {};
    }
}
