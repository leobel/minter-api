import ByronGenesis from './mainnet-byron-genesis.json';
import ShelleyGenesis from './mainnet-shelley-genesis.json';
import AlonzoGenesis from './mainnet-alonzo-genesis.json';
import Protocols from './mainnet-protocol.json';

import TestnetByronGenesis from './testnet-byron-genesis.json';
import TestnetShelleyGenesis from './testnet-shelley-genesis.json';
import TestnetAlonzoGenesis from './testnet-alonzo-genesis.json';
import TestnetProtocols from './testnet-protocol.json';

import LocalClusterByronGenesis from './local-cluster-byron-genesis.json';
import LocalClusterShelleyGenesis from './local-cluster-shelley-genesis.json';
import LocalClusterAlonzoGenesis from './local-cluster-alonzo-genesis.json';
import LocalClusterProtocols from './local-cluster-protocol.json';

export const Mainnet = {
    byron: ByronGenesis,
    shelley: ShelleyGenesis,
    alonzo: AlonzoGenesis,
    protocols: Protocols

}

export const Testnet = {
    byron: TestnetByronGenesis,
    shelley: TestnetShelleyGenesis,
    alonzo: TestnetAlonzoGenesis,
    protocols: TestnetProtocols
}

export const LocalCluster = {
    byron: LocalClusterByronGenesis,
    shelley: LocalClusterShelleyGenesis,
    alonzo: LocalClusterAlonzoGenesis,
    protocols: LocalClusterProtocols
}