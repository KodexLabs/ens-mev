# ENS-Sniper

This is a bot which accepts a text file as input and then attempts to
register the ENS names within via flashbots. It watches the state of
the ens registrations requested every block, and checks if they can
be registered.

Configuration
This tool is configured via the following environment variables:

```ETH_RPC_WS=ws://your-eth-client-websockets:port
PRIVATE_KEY=private key of wallet to register with
FLASHBOTS_KEY=signing key to use for flashbots bundles
SIMULATE_ONLY=Simulate bundles if set to any value
TESTNET=Operate on goerli testnet if set to any value
REGISTRATIONS_FILE=.ron file to read registration info from
RUST_LOG(optional)=Log level```
