# ENS-Sniper

This is a bot which accepts a text file as input and then attempts to
register the ENS names within via Flashbots. It watches the state of
the ENS registrations requested every block, and checks if they can
be registered. 

*Note: This bot was only applicable to the legacy ENS declining premium auctions, which were set at $2000. ENS Protocol has since increased the starting price of the dutch-auction to $100m, rendering a bot such as this one irrelevant. Hence, we are open sourcing it. 

Author: [0xAlcibiades](https://github.com/0xAlcibiades)

## Configuration
This tool is configured via the following environment variables:

```ETH_RPC_WS=ws://your-eth-client-websockets:port
PRIVATE_KEY=private key of wallet to register with
FLASHBOTS_KEY=signing key to use for Flashbots bundles
SIMULATE_ONLY=Simulate bundles if set to any value
TESTNET=Operate on goerli testnet if set to any value
REGISTRATIONS_FILE=.ron file to read registration info from
RUST_LOG(optional)=Log level
```



