
import { CoinSelectionWallet } from './wallet/coin-selection-wallet';
import { Address, AssetName, Assets, AuxiliaryData, BaseAddress, BigNum, Bip32PrivateKey, Bip32PublicKey, ByronAddress, Certificate, Certificates, DataCost, DataHash, Ed25519KeyHash, Ed25519Signature, EnterpriseAddress, GeneralTransactionMetadata, hash_auxiliary_data, hash_plutus_data, hash_transaction, Int, LinearFee, make_vkey_witness, MetadataList, MetadataMap, Mint, MintAssets, min_ada_for_output, min_fee, MultiAsset, NativeScript, NativeScripts, NetworkInfo, PlutusData, PlutusList, PrivateKey, PublicKey, ScriptAll, ScriptAny, ScriptHash, ScriptNOfK, ScriptPubkey, StakeCredential, StakeDelegation, TimelockExpiry, TimelockStart, Transaction, TransactionBody, TransactionBuilder, TransactionBuilderConfigBuilder, TransactionHash, TransactionInput, TransactionInputs, TransactionMetadatum, TransactionOutput, TransactionOutputs, TransactionWitnessSet, Value, Vkeywitnesses, BigInt, ConstrPlutusData, hash_script_data, Redeemers, TxBuilderConstants, PlutusScripts, PlutusScript, Redeemer, RedeemerTag, ExUnits, Ed25519KeyHashes, Languages, UnitInterval, ScriptRef, FixedTransaction, RewardAddress, TransactionUnspentOutput, TxInputsBuilder, min_script_fee, ExUnitPrices } from '@emurgo/cardano-serialization-lib-nodejs';
import { Mainnet } from './config/network.config';
import { TokenWallet } from './wallet/token-wallet';
import { ApiCoinSelectionChange, ApiCoinSelectionInputs, WalletsAssetsAvailable, WalletswalletIdpaymentfeesAmountUnitEnum, WalletswalletIdpaymentfeesPayments } from './models';
import { AssetWallet } from './wallet/asset-wallet';
import { Script } from './models/script.model';
import { JsonScript, ScriptTypeEnum, scriptTypes } from './models/json-script.model';
import { ExtendedSigningKey } from './models/payment-extended-signing-key';
import { MultisigTransaction } from './models/multisig-transaction';
import blake2b from 'blake2b';
import * as _ from 'lodash';

const phrasesLengthMap: { [key: number]: number } = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256
}

export const CIP68_REFERENCE_PREFIX = '000643b0';
export const CIP68_NFT_PREFIX = '000de140';
export const CIP68_RNFT_PREFIX = '001bc280';
export const CIP68_FT_PREFIX = '0014df10';
export const CIP68_STANDARD: { [key: string]: number } = {
    [CIP68_REFERENCE_PREFIX]: 100, // Reference Token
    [CIP68_NFT_PREFIX]: 222, // NFT Token
    [CIP68_FT_PREFIX]: 333, // FT Token
    [CIP68_RNFT_PREFIX]: 444 // RNFT Token
}
const UNPRINTABLE_CHARACTERS_REGEXP = /[\p{Cc}\p{Cn}\p{Cs}]+/gu;

export class Seed {
    static toMnemonicList(phrase: string): Array<string> {
        return phrase.trim().split(/\s+/g);
    }

    static deriveAccountKey(key: Bip32PrivateKey, index: number = 0): Bip32PrivateKey {
        return key
            .derive(Seed.harden(CARDANO_PUROPOSE)) // purpose
            .derive(Seed.harden(CARDANO_COIN_TYPE)) // coin type
            .derive(Seed.harden(index)); // account #0
    }

    static deriveKey(key: Bip32PrivateKey, path: string[]): Bip32PrivateKey {
        let result = key;
        path.forEach(p => {
            result = result.derive(p.endsWith('H') || p.endsWith("'")
                ? Seed.harden(Number.parseInt(p.substr(0, p.length - 1)))
                : Number.parseInt(p))
        });

        return result;
    }

    static buildTransaction(coinSelection: CoinSelectionWallet, ttl: number, opts: { [key: string]: any } = { changeAddress: "", metadata: null as any, startSlot: 0, config: Mainnet, certificates: null }): TransactionBody {
        let config = opts.config || Mainnet;
        let metadata = opts.metadata;
        let certificates = opts.certificates;
        let startSlot = opts.startSlot || 0;
        let tbConfig = TransactionBuilderConfigBuilder.new()
            // all of these are taken from the mainnet genesis settings
            // linear fee parameters (a*size + b)
            .fee_algo(LinearFee.new(toBigNum(config.protocols.txFeePerByte), toBigNum(config.protocols.txFeeFixed)))
            //min-ada-value
            .coins_per_utxo_word(toBigNum(config.protocols.utxoCostPerWord))
            // pool deposit
            .pool_deposit(toBigNum(config.protocols.stakePoolDeposit))
            // key deposit
            .key_deposit(toBigNum(config.protocols.stakeAddressDeposit))
            // max output value size
            .max_value_size(config.protocols.maxValueSize)
            // max tx size
            .max_tx_size(config.protocols.maxTxSize)
            .build();

        let txBuilder = TransactionBuilder.new(tbConfig);

        // add tx inputs
        coinSelection.inputs.forEach((input, i) => {
            let address = Seed.getAddress(input.address);
            let txInput = TransactionInput.new(
                TransactionHash.from_bytes(Buffer.from(input.id, 'hex')),
                input.index
            );
            let amount = Value.new(
                toBigNum(input.amount.quantity)
            );

            txBuilder.add_input(address, txInput, amount);
        });

        // add tx outputs
        coinSelection.outputs.forEach(output => {
            let address = Seed.getAddress(output.address);
            let amount = Value.new(
                toBigNum(output.amount.quantity)
            );

            // add tx assets
            if (output.assets && output.assets.length > 0) {
                let multiAsset = Seed.buildMultiAssets(output.assets);
                amount.set_multiasset(multiAsset);
            }

            let txOutput = TransactionOutput.new(
                address,
                amount
            );
            txBuilder.add_output(txOutput);
        });

        // add tx change
        coinSelection.change.forEach(change => {
            let address = Seed.getAddress(change.address);
            let amount = Value.new(
                toBigNum(change.amount.quantity)
            );

            // add tx assets
            if (change.assets && change.assets.length > 0) {
                let multiAsset = Seed.buildMultiAssets(change.assets);
                amount.set_multiasset(multiAsset);
            }

            let txOutput = TransactionOutput.new(
                address,
                amount
            );
            txBuilder.add_output(txOutput);
        });

        // add tx metadata
        if (metadata) {
            txBuilder.set_auxiliary_data(metadata);
        }

        // add certificates
        if (certificates) {
            const certs = Seed.buildCertificates(certificates)
            txBuilder.set_certs(certs);
        }

        // set tx validity start interval
        txBuilder.set_validity_start_interval(startSlot);

        // set tx ttl
        txBuilder.set_ttl(ttl);

        // calculate fee
        if (opts.changeAddress) { // don't take the implicit fee
            let address = Seed.getAddress(opts.changeAddress);
            txBuilder.add_change_if_needed(address);
        } else {
            let fee = opts.fee || coinSelection.inputs.reduce((acc, c) => c.amount.quantity + acc, 0)
                + (coinSelection.withdrawals?.reduce((acc, c) => c.amount.quantity + acc, 0) || 0)
                - coinSelection.outputs.reduce((acc, c) => c.amount.quantity + acc, 0)
                - coinSelection.change.reduce((acc, c) => c.amount.quantity + acc, 0)
                - (coinSelection.deposits?.reduce((acc, c) => c.quantity + acc, 0) || 0);
            txBuilder.set_fee(toBigNum(fee));
        }
        let txBody = txBuilder.build();
        return txBody;
    }

    static buildCertificates(certificates: { type: string, address: string, pool_hash: string }[]): Certificates {
        const certs = Certificates.new();
        for (const certificate of certificates) {
            switch (certificate.type) {
                case 'delegation': {
                    const delegation = Seed.buildStakeDelegation(certificate)
                    const cert = Certificate.new_stake_delegation(delegation);
                    certs.add(cert);
                    break;
                }
                case 'registration':

                    break;
                default:
                    break;
            }
        }
        return certs;
    }

    static buildStakeDelegation(certificate: { type: string, address: string, pool_hash: string }): StakeDelegation {
        const baseAddr = BaseAddress.from_address(Seed.getAddress(certificate.address));
        const stakeCredential = baseAddr!.stake_cred();
        const poolKeyHash = Ed25519KeyHash.from_hex(certificate.pool_hash);
        return StakeDelegation.new(stakeCredential, poolKeyHash);
    }

    static buildTransactionWithToken(coinSelection: CoinSelectionWallet, ttl: number, tokens: TokenWallet[], signingKeys: PrivateKey[], opts: { [key: string]: any } = { changeAddress: "", data: null as any, startSlot: 0, config: Mainnet }, encoding: BufferEncoding = 'hex'): TransactionBody {
        let metadata = opts.data ? Seed.buildTransactionMetadata(opts.data) : undefined;
        opts.config = opts.config || Mainnet;
        // set maximun fee first
        const fee = parseInt(opts.config.protocols.maxTxSize * opts.config.protocols.txFeePerByte + opts.config.protocols.txFeeFixed); // 16384 * 44 + 155381 = 876277
        if (!opts.fee) {
            opts.fee = fee;
            // adjust change if there is any
            if (coinSelection.change && coinSelection.change.length > 0) {
                const selectionfee = coinSelection.inputs.reduce((acc, c) => c.amount.quantity + acc, 0)
                    + (coinSelection.withdrawals?.reduce((acc, c) => c.amount.quantity + acc, 0) || 0)
                    - coinSelection.outputs.reduce((acc, c) => c.amount.quantity + acc, 0)
                    - coinSelection.change.reduce((acc, c) => c.amount.quantity + acc, 0)
                    - (coinSelection.deposits?.reduce((acc, c) => c.quantity + acc, 0) || 0);

                const feePerChange = Math.ceil((opts.fee - selectionfee) / coinSelection.change.length);
                coinSelection.change = coinSelection.change.map(change => {
                    change.amount.quantity -= feePerChange;
                    return change;
                });
            }
        }


        let buildOpts = Object.assign({}, { metadata: metadata, ...opts });

        // create mint token data
        let mint = Seed.buildTransactionMint(tokens, encoding);

        // get token's scripts 
        let scripts = tokens.map(t => t.script!);

        // set mint into tx
        let txBody = Seed.buildTransaction(coinSelection, ttl, buildOpts);
        txBody.set_mint(mint);

        // sign to calculate the real tx fee;
        let tx = Seed.sign(txBody, signingKeys, metadata, scripts);

        // NOTE: txFee should be <= original fee = maxTxSize * txFeePerByte + txFeeFixed
        // Also after rearrange the outputs will decrease along with fee field, so new tx fee won't increase because tx's size (bytes) will be smaller;
        const txFee = Seed.getTransactionFee(tx, false, opts.config);
        // if (txFee > fee) throw new Error(`expected tx size less than ${opts.config.protocols.maxTxSize} but got: ${(txFee - opts.config.protocols.txFeeFixed)/opts.config.protocols.txFeePerByte}`)

        const finalFee = txFee;
        // const finalFee = Math.min(txFee, (fee || Number.MAX_SAFE_INTEGER)); // we'll use the min fee on final tx
        opts.fee = finalFee;

        // adjust change UTXO
        const feeDiff = fee - finalFee;
        if (coinSelection.change && coinSelection.change.length > 0) {
            const feeDiffPerChange = Math.ceil(feeDiff / coinSelection.change.length);
            coinSelection.change = coinSelection.change.map(c => {
                c.amount.quantity += feeDiffPerChange;
                return c;
            });
        }

        // after signing the metadata is cleaned so we need to create it again
        metadata = opts.data ? Seed.buildTransactionMetadata(opts.data) : undefined;
        buildOpts = Object.assign({}, { metadata: metadata, ...opts });

        txBody = Seed.buildTransaction(coinSelection, ttl, buildOpts);
        txBody.set_mint(mint);

        return txBody;
    }


    static buildTransactionForEvaluation(
        coinSelection: CoinSelectionWallet,
        ttl: number,
        tokens: TokenWallet[] = [],
        signingKeys: PrivateKey[] = [],
        plutusScripts: { purpose: RedeemerTag, script: PlutusScript, data: any, exUnits: ExUnits, inputData?: any, ctrIndex?: number }[] = [],
        opts: { [key: string]: any } = { changeAddress: "", data: null, startSlot: 0, config: Mainnet },
        collateral?: { inputs: TransactionInput[], output?: TransactionOutput }, encoding: BufferEncoding = 'hex'
    ): Transaction {
        const config = opts.config || Mainnet;
        let metadata = opts.data ? Seed.buildTransactionMetadata(opts.data) : undefined;
        const certificates = opts.certificates;
        const startSlot = opts.startSlot || 0;
        const selectionfee = parseInt(config.protocols.maxTxSize * config.protocols.txFeePerByte + config.protocols.txFeeFixed); // 16384 * 44 + 155381 = 876277
        const currentfee = coinSelection.inputs.reduce((acc, c) => c.amount.quantity + acc, 0)
            + (coinSelection.withdrawals?.reduce((acc, c) => c.amount.quantity + acc, 0) || 0)
            - coinSelection.outputs.reduce((acc, c) => c.amount.quantity + acc, 0)
            - coinSelection.change.reduce((acc, c) => c.amount.quantity + acc, 0)
            - (coinSelection.deposits?.reduce((acc, c) => c.quantity + acc, 0) || 0);


        const plutusData = PlutusList.new();
        const smartContracts = PlutusScripts.new();
        const redeemers = Redeemers.new();
        const languages = Languages.new();

        // add tx inputs
        const inputs = coinSelection.inputs.map((input) => {
            return TransactionInput.new(
                TransactionHash.from_bytes(Buffer.from(input.id, 'hex')),
                input.index
            );
        });

        // add tx outputs
        let outputs = coinSelection.outputs.map(output => {
            let address = Seed.getAddress(output.address);
            let amount = Value.new(
                toBigNum(output.amount.quantity)
            );

            // add tx assets
            if (output.assets && output.assets.length > 0) {
                let multiAsset = Seed.buildMultiAssets(output.assets, encoding);
                amount.set_multiasset(multiAsset);
            }

            const utxo = TransactionOutput.new(
                address,
                amount
            );

            // add plutus data
            if (output.data) {
                Seed.addPlutusData(output, utxo, plutusData);
            }
            return utxo;
        });

        // adjust changes to match maximum fee
        if (coinSelection.change && coinSelection.change.length > 0) {
            const feeDiff = selectionfee - currentfee;
            const feeDiffPerChange = Math.abs(Math.ceil(feeDiff / coinSelection.change.length));
            for (let i = 0; i < coinSelection.change.length; i++) {
                const change = coinSelection.change[i];
                change.amount.quantity = feeDiff > 0 ? change.amount.quantity - feeDiffPerChange : change.amount.quantity + feeDiffPerChange;

                let address = Seed.getAddress(change.address);
                let amount = Value.new(
                    toBigNum(change.amount.quantity)
                );

                // add tx assets
                if (change.assets && change.assets.length > 0) {
                    let multiAsset = Seed.buildMultiAssets(change.assets, encoding);
                    amount.set_multiasset(multiAsset);
                }

                const utxo = TransactionOutput.new(
                    address,
                    amount
                );

                // add plutus data
                if (change.data) {
                    Seed.addPlutusData(change, utxo, plutusData);
                }

                outputs.push(utxo);
            }
        }

        const txInputs = TransactionInputs.new();
        inputs.forEach(txin => txInputs.add(txin));
        let txOutputs = TransactionOutputs.new();
        outputs.forEach(txout => txOutputs.add(txout));
        const txBody = TransactionBody.new(txInputs, txOutputs, toBigNum(selectionfee), ttl);

        // add tx metadata
        if (metadata) {
            const dataHash = hash_auxiliary_data(metadata);
            txBody.set_auxiliary_data_hash(dataHash)
        }

        // add tokens
        if (tokens.length > 0) {
            // create mint token data
            const mint = Seed.buildTransactionMint(tokens, encoding);
            txBody.set_mint(mint);
        }

        // add certificates
        if (certificates) {
            const certs = Seed.buildCertificates(certificates)
            txBody.set_certs(certs);
        }

        // set tx validity start interval
        txBody.set_validity_start_interval(startSlot);

        if (plutusScripts.length > 0) {
            if (signingKeys.length > 0) {
                const signerKeys = Ed25519KeyHashes.new();
                signingKeys.forEach(key => signerKeys.add(key.to_public().hash()));
                txBody.set_required_signers(signerKeys);
            }
            for (let i = 0; i < plutusScripts.length; i++) {
                const { purpose, script, data, inputData, ctrIndex } = plutusScripts[i];
                smartContracts.add(script);
                const redeemer = Seed.buildRedeemer(purpose, i, ExUnits.new(toBigNum(0), toBigNum(0)), ctrIndex || 0, data);
                redeemers.add(redeemer);
                if (inputData) { // datum for spending script
                    const pData = PlutusData.new_constr_plutus_data(ConstrPlutusData.from_hex(inputData));
                    console.log('Hash DATA', hash_plutus_data(pData).to_hex())
                    plutusData.add(pData);
                }
            }
            // TODO: apply dynamic logic here
            if (collateral) {
                const collateralInputs = TransactionInputs.new();
                collateral?.inputs.forEach(input => collateralInputs.add(input))
                txBody.set_collateral(collateralInputs);
                if (collateral?.output) {
                    txBody.set_collateral_return(collateral.output);
                }
            }
        }

        if (plutusData.len() > 0 || redeemers.len() > 0) {
            const allCostModels = TxBuilderConstants.plutus_vasil_cost_models();
            const costModels = languages.len() > 0 ? allCostModels.retain_language_versions(languages) : allCostModels;
            // we need to clone the plutusData since getting the script_hash free the plutusData parameter and we need to pass it to MultisigTransaction
            const scriptDataHash = hash_script_data(redeemers, costModels, PlutusData.new_list(plutusData).as_list());
            txBody.set_script_data_hash(scriptDataHash);
        }

        console.log('Tx Body:', txBody.to_json());


        const witnessSet = TransactionWitnessSet.new();
        if (plutusData.len() > 0) {
            witnessSet.set_plutus_data(plutusData);
        }

        if (smartContracts.len() > 0) {
            witnessSet.set_plutus_scripts(smartContracts);
        }
        if (redeemers.len() > 0) {
            witnessSet.set_redeemers(redeemers);
        }
        return Transaction.new(
            txBody,
            witnessSet
        )
    }

    static buildTransactionMultisig(
        total: number,
        utxos: TransactionUnspentOutput[],
        outputs: WalletswalletIdpaymentfeesPayments[],
        change: ApiCoinSelectionChange[],
        ttl: number,
        tokens: TokenWallet[],
        scripts: NativeScript[],
        signingKeys: PrivateKey[],
        requirePolicyKeys: Ed25519KeyHash[],
        plutusScripts: { purpose: RedeemerTag, script: PlutusScript, exUnits: ExUnits, index: number, scriptRef?: { hash: string, index: number }, inputData?: any, ctr?: number, data?: any }[] = [],
        collateralInputs: TransactionUnspentOutput[] = [],
        opts: { [key: string]: any } = {
            changeAddress: '',
            data: null as any,
            startSlot: 0,
            config: Mainnet,
        },
        encoding: BufferEncoding = 'hex'
    ): MultisigTransaction {
        const config = opts.config || Mainnet;
        let metadata = opts.data ? Seed.buildTransactionMetadata(opts.data) : undefined;

        const startSlot = opts.startSlot || 0;
        const selectionfee = parseInt(config.protocols.maxTxSize * config.protocols.txFeePerByte + config.protocols.txFeeFixed) +  // 16384 * 44 + 155381 = 876277
            (
                plutusScripts.length == 0
                    ? 0
                    : Seed.calculateScriptExecutionCost(config.protocols.maxTxExecutionUnits.memory, Number(config.protocols.executionUnitPrices.priceMemory), config.protocols.maxTxExecutionUnits.steps, Number(config.protocols.executionUnitPrices.priceSteps)) // 1528800
            );
        const collateralPercentage = config.protocols.collateralPercentage / 100; // 1,5
        const maxCollateralInputs = config.protocols.maxCollateralInputs;

        // witnesses set redeemers, datums and plutus scripts
        const plutusData = PlutusList.new();
        const smartContracts = PlutusScripts.new();
        const referenceInputs = TransactionInputs.new();
        const redeemers = Redeemers.new();
        const languages = Languages.new();

        // add witnesses Public Key Ed25519KeyHash from input addresses and require signers
        const vkeys: { [key: string]: number } = signingKeys.reduce((dict: { [key: string]: number }, key) => {
            const hash = key.to_public().hash().to_hex();
            if (!dict[hash]) {
                dict[hash] = 1
            }
            return dict;
        }, requirePolicyKeys.reduce((dict: { [key: string]: number }, key) => {
            const hash = key.to_hex();
            if (!dict[hash]) {
                dict[hash] = 1
            }
            return dict;
        }, {}));

        // collateral candidates
        const maxCollateralSum = Math.ceil(selectionfee * collateralPercentage);
        let { collateralCandidates, collateralCandidatesAda, collateralSum } = collateralInputs.reduce<{ collateralSum: number, collateralCandidatesAda: number[], collateralCandidates: { amount: Value, input: TransactionInput, address: Address }[] }>((dict, u) => {
            const output = u.output();
            const input = u.input();
            const amount = output.amount();
            const address = output.address();
            const coin = parseInt(amount.coin().to_str());
            const { collateralSum, collateralCandidatesAda, collateralCandidates } = dict;
            collateralCandidatesAda.push(coin);
            collateralCandidates.push({ amount, input, address });
            return { collateralSum: collateralSum + coin, collateralCandidatesAda, collateralCandidates }
        }, { collateralSum: 0, collateralCandidatesAda: [], collateralCandidates: [] });

        // tx inputs
        const inputs = utxos.map(u => {
            const output = u.output();
            const input = u.input();
            const amount = output.amount();
            const addr = output.address();
            if (plutusScripts.length > 0 && collateralSum < maxCollateralSum) {
                const coin = parseInt(amount.coin().to_str());
                let index = Seed.getCollateralIndex(collateralCandidatesAda, coin, maxCollateralInputs);
                if (index >= 0) {
                    collateralSum += coin;
                    collateralCandidatesAda.splice(index, 0, coin)
                    collateralCandidates.splice(index, 0, { amount, address: addr, input });
                }
            }
            const pKeyHash = Seed.getAddressPaymentKeyHash(addr);
            if (pKeyHash && !vkeys[pKeyHash]) {
                vkeys[pKeyHash] = 1;
            }
            return input;
        });

        // tx outputs
        const outs = outputs.map(output => {
            let address = Seed.getAddress(output.address);
            let amount = Value.new(
                toBigNum(output.amount.quantity)
            );

            // add tx assets
            if (output.assets && output.assets.length > 0) {
                let multiAsset = Seed.buildMultiAssets(output.assets, encoding);
                amount.set_multiasset(multiAsset);
            }

            const utxo = TransactionOutput.new(
                address,
                amount
            );

            if (output.data) {
                Seed.addPlutusData(output, utxo, plutusData);
            }

            // add script_ref
            if (output.script_ref) {
                utxo.set_script_ref(ScriptRef.from_hex(output.script_ref));
            }

            return utxo;
        });

        // set body fee with the maximum fee based on tx's size
        // change (use buyer as change in order to apply any rearrenge to them)
        // add change entirely without deducting fees . Tx at this state is invalid, adjustFee will deduct fee from changes and create a valid tx (changes could end discarded)
        if (change && change.length > 0) {
            // const feeDiffPerChange = Math.abs(Math.ceil(selectionfee / change.length));
            for (let i = 0; i < change.length; i++) {
                const ch = change[i];
                // ch.amount.quantity -= feeDiffPerChange;

                let address = Seed.getAddress(ch.address);
                let amount = Value.new(
                    toBigNum(ch.amount.quantity)
                );

                // add tx assets
                if (ch.assets && ch.assets.length > 0) {
                    let multiAsset = Seed.buildMultiAssets(ch.assets, encoding);
                    amount.set_multiasset(multiAsset);
                }

                const utxo = TransactionOutput.new(
                    address,
                    amount
                );

                // add plutus data
                if (ch.data) {
                    Seed.addPlutusData(ch, utxo, plutusData);
                }

                // add script_ref
                if (ch.script_ref) {
                    utxo.set_script_ref(ScriptRef.from_hex(ch.script_ref));
                }

                outs.push(utxo);
            }
        }

        const txInputs = TransactionInputs.new();
        inputs.forEach(txin => txInputs.add(txin));
        let txOutputs = TransactionOutputs.new();
        outs.forEach(txout => txOutputs.add(txout));
        const txBody = TransactionBody.new_tx_body(txInputs, txOutputs, toBigNum(selectionfee));
        if (ttl) {
            txBody.set_ttl(toBigNum(ttl));
        }

        // add tx metadata
        if (metadata) {
            const dataHash = hash_auxiliary_data(metadata);
            txBody.set_auxiliary_data_hash(dataHash)
        }

        if (tokens) {
            // create mint token data
            const mint = Seed.buildTransactionMint(tokens, encoding);
            txBody.set_mint(mint);
        }

        if (plutusScripts.length > 0) {
            // add require_signers for plutus script
            if (requirePolicyKeys.length > 0) {
                const signerKeys = Ed25519KeyHashes.new();
                requirePolicyKeys.forEach(key => signerKeys.add(key));
                txBody.set_required_signers(signerKeys);
            }

            // add collateral
            const { inputs, vkeys: cVKeys, output } = Seed.buildCollateral(collateralCandidates.slice(0, maxCollateralInputs), maxCollateralSum, config);
            txBody.set_collateral(inputs);
            // include collateral inputs on signers
            for (const [pkeyHash, n] of Object.entries(cVKeys)) {
                if (!vkeys[pkeyHash]) {
                    vkeys[pkeyHash] = n;
                }
            }

            if (output) {
                txBody.set_collateral_return(output);
            }

            for (let i = 0; i < plutusScripts.length; i++) {
                const { purpose, script, index, scriptRef, exUnits, data, inputData, ctr } = plutusScripts[i];
                languages.add(script.language_version());
                if (scriptRef) {
                    referenceInputs.add(TransactionInput.new(
                        TransactionHash.from_hex(scriptRef.hash),
                        scriptRef.index
                    ))
                } else {
                    smartContracts.add(script);
                }
                const redeemer = Seed.buildRedeemer(purpose, index, exUnits, ctr || 0, data);
                redeemers.add(redeemer);
                if (inputData) { // datum for spending script
                    const pData = PlutusData.from_hex(inputData);
                    plutusData.add(pData);
                }
            }
        }

        // check outside plutus script since native scripts can be passed as reference inputs as well
        if (referenceInputs.len() > 0) {
            txBody.set_reference_inputs(referenceInputs);
        }

        // set datums witnesses
        if (plutusData.len() > 0 || redeemers.len() > 0) {
            const allCostModels = TxBuilderConstants.plutus_vasil_cost_models();
            const costModels = languages.len() > 0 ? allCostModels.retain_language_versions(languages) : allCostModels;
            // we need to clone the plutusData since getting the script_hash free the plutusData parameter and we need to pass it to MultisigTransaction
            const datums = plutusData.len() > 0 ? PlutusData.new_list(plutusData).as_list() : undefined;
            const scriptDataHash = hash_script_data(redeemers, costModels, datums);
            txBody.set_script_data_hash(scriptDataHash);
        }

        // set tx validity start interval
        txBody.set_validity_start_interval(startSlot);

        // add inputs witnesses
        return MultisigTransaction.new(total, outputs, change, txBody, scripts, smartContracts, redeemers, plutusData, collateralCandidates.slice(0, maxCollateralInputs), signingKeys, vkeys, config, encoding, metadata, tokens);
    }

    static getTxRequireSigners(tx: Transaction): Set<string> {
        const signers = new Set<string>();

        const txBody = tx.body()

        // script require signers
        const requireSigners = txBody.required_signers();
        if (requireSigners) {
            for (let i = 0; i < requireSigners.len(); i++) {
                const edKeyHash = requireSigners.get(i);
                signers.add(edKeyHash.to_hex());
            }
        }

        return signers;
    }

    private static getCollateralIndex(collateralCandidatesAda: number[], coin: number, maxCollateralInputs: any) {
        let index = collateralCandidatesAda.findIndex(c => c < coin);
        if (index < 0 && collateralCandidatesAda.length < maxCollateralInputs) {
            index = Math.max(collateralCandidatesAda.length - 1, 0);
        }
        return index;
    }

    static getAddressPaymentKeyHash(address: string | Address): string | undefined {
        try {
            const addr = typeof address == 'string' ? Address.from_bech32(address) : address;
            const baseAddr = BaseAddress.from_address(addr) || EnterpriseAddress.from_address(addr);
            return baseAddr?.payment_cred()?.to_keyhash()?.to_hex();
        } catch (err) {
            return undefined;
        }
    }

    static buildCollateral(candidates: { amount: Value, address: Address, input: TransactionInput }[], maxCollateral: number, config: any): { inputs: TransactionInputs, inputsBuilder: TxInputsBuilder, vkeys: { [key: string]: number }, output?: TransactionOutput } {
        let inputTotal = 0;
        let assets = {};
        const collateralInputs = TransactionInputs.new();
        const collateralInputsBuilder = TxInputsBuilder.new();
        const vkeys: { [key: string]: number } = {};
        for (let { amount, address, input } of candidates) {
            collateralInputs.add(input);
            collateralInputsBuilder.add_input(address, input, amount);
            const pKeyHash = Seed.getAddressPaymentKeyHash(address);
            if (pKeyHash && !vkeys[pKeyHash]) {
                vkeys[pKeyHash] = 1;
            }
            inputTotal += Number(amount.coin().to_str());
            const inputAssets = amount.multiasset();
            if (inputAssets && inputAssets.len() > 0) {
                const assetsMap = JSON.parse(inputAssets.to_json());
                assets = _.merge(assets, assetsMap);
            }
            if (inputTotal >= maxCollateral) {
                break;
            }
        }

        const collateralReturn = Math.floor(inputTotal - maxCollateral);
        // console.log('Collateral return', collateralReturn);
        // console.log('Collateral Assets:', assets);

        if (collateralReturn < 0) {
            throw new Error("Not enough funds for collateral");
        }
        const result: { inputs: TransactionInputs, inputsBuilder: TxInputsBuilder, vkeys: { [key: string]: number }, output?: TransactionOutput } = { inputs: collateralInputs, inputsBuilder: collateralInputsBuilder, vkeys };
        const address = candidates[0].address;
        const withAssets = Object.keys(assets).length > 0;
        if (collateralReturn >= (Seed.getMinUtxoValue(address, config))) {
            result.output = TransactionOutput.new(
                typeof address == 'string' ? Address.from_bech32(address) : address,
                withAssets
                    ? Value.new_with_assets(toBigNum(collateralReturn), MultiAsset.from_json(JSON.stringify(assets)))
                    : Value.new(toBigNum(collateralReturn))
            )

        }
        return result;
    }

    static calculateScriptExecutionCost(memExUnits: number, memExUnitsPirce: number, stepExUnits: number, stepExUnitsPrice: number): number {
        return Math.ceil((memExUnits * memExUnitsPirce) + (stepExUnits * stepExUnitsPrice));
    }

    static addPlutusData(output: ApiCoinSelectionChange | WalletswalletIdpaymentfeesPayments, utxo: TransactionOutput, plutusData?: PlutusList) {
        if (output.data?.inline) {
            utxo.set_plutus_data(PlutusData.from_hex(output.data.inline));
        } else if (output.data?.asHash) {
            const data = PlutusData.from_hex(output.data.asHash);
            utxo.set_data_hash(hash_plutus_data(data));
            if (plutusData) {
                plutusData.add(data);
            }
        }
        else {
            utxo.set_data_hash(DataHash.from_hex(output.data?.hash!));
        }
    }

    static buildRedeemer(tag: RedeemerTag, index: number, exUnits: ExUnits, ctrIndex = 0, data?: any): Redeemer {
        const fields = PlutusList.new();
        if (data) {
            const rawData = Seed.buildPlutusData(data);
            const pData = PlutusData.from_json(JSON.stringify(rawData), 1);
            fields.add(pData);
        }
        const plutusData = PlutusData.new_constr_plutus_data(
            ConstrPlutusData.new(toBigNum(ctrIndex), fields)
        )
        return Redeemer.new(tag, toBigNum(index), plutusData, exUnits);
    }

    static getMintRedeemerIndex(scripts: { purpose: RedeemerTag, script: PlutusScript, index: number, scriptRef?: { hash: string, index: number }, data?: any, exUnits: ExUnits }[]) {
        return scripts.sort((a, b) => {
            const pa = Seed.getScriptHash(a.script).to_hex();
            const pb = Seed.getScriptHash(b.script).to_hex();
            return pa == pb ? 0 : pa < pb ? -1 : 1;
        })
            .map((sc, i) => ({ ...sc, index: i }));
    }

    static getAddressKeyHash(addr: string): string | undefined {
        return BaseAddress.from_address(Address.from_bech32(addr))
            ?.payment_cred()
            .to_keyhash()
            ?.to_hex()
    }

    static getScriptHashFromPlutusScript(script: string, version = 2): ScriptHash {
        return version == 1 ?
            PlutusScript.from_bytes(Buffer.from(script, 'hex')).hash() :
            PlutusScript.from_bytes_v2(Buffer.from(script, 'hex')).hash();
    }

    static getRefenceTokenUtxos(tokens: TokenWallet[], config: any, version = 1, extra?: any) {
        const utxos: any = [];
        for (const token of tokens.filter(t => t.referenceAddress)) {
            // metadata BuiltinData
            const rawMetadata = Seed.buildPlutusData(token.metadata);
            const metadataBuiltinData = PlutusData.from_json(JSON.stringify(rawMetadata), 1);

            // version number
            const versionData = PlutusData.new_integer(BigInt.from_str(version.toString()));

            // extra BuiltinData (empty list = 121([]))
            const extraList = PlutusList.new();
            if (extra) {
                const plutusExtra = PlutusData.from_json(JSON.stringify(Seed.buildPlutusData(extra)), 1)
                extraList.add(plutusExtra);
            }
            const extraBuiltinData = PlutusData.new_constr_plutus_data(
                ConstrPlutusData.new(toBigNum(0), extraList)
            )

            const fields = PlutusList.new();
            fields.add(metadataBuiltinData);
            fields.add(versionData);
            fields.add(extraBuiltinData);

            const plutusData = PlutusData.new_constr_plutus_data(
                ConstrPlutusData.new(toBigNum(0), fields)
            )
            const plutusDataHash = hash_plutus_data(plutusData);
            const address = Seed.getAddress(token.referenceAddress!);
            const asset_name = Seed.buildCip68ReferenceAssetName(token.asset.policy_id, token.asset.asset_name);
            const asset = { policy_id: token.asset.policy_id, asset_name, quantity: 1 };
            const minAda = Seed.getMinUtxoValueWithAssets(address, [asset], plutusDataHash, null, config, 'hex');

            const output: any = {
                amount: {
                    quantity: minAda,
                    unit: WalletswalletIdpaymentfeesAmountUnitEnum.Lovelace
                },
                address: token.referenceAddress,
                assets: [asset],
                data: { asHash: plutusData.to_hex() },

            }

            // add referen token utxo to coin selection
            utxos.push(output);

        }
        return utxos;
    }

    static getAddress(addr: string): Address {
        try {
            return Address.from_bech32(addr);
        } catch (error) {
            return ByronAddress.from_base58(addr).to_address();
        }
    }

    static buildMultiAssets(assets: WalletsAssetsAvailable[], encoding: BufferEncoding = 'hex'): MultiAsset {
        let multiAsset = MultiAsset.new();
        const groups = assets.reduce((dict: { [key: string]: WalletsAssetsAvailable[] }, asset: WalletsAssetsAvailable) => {
            (dict[asset.policy_id] = dict[asset.policy_id] || []).push(asset);
            return dict;
        }, {});
        for (const policy_id in groups) {
            const scriptHash = Seed.getScriptHashFromPolicy(policy_id);
            let asset = Assets.new();
            const assetGroups = groups[policy_id].reduce((dict: { [key: string]: number }, asset: WalletsAssetsAvailable) => {
                dict[asset.asset_name] = (dict[asset.asset_name] || 0) + +asset.quantity;
                return dict;
            }, {});
            for (const asset_name in assetGroups) {
                const quantity = assetGroups[asset_name];
                const assetName = AssetName.new(Buffer.from(asset_name, encoding));
                asset.insert(assetName, toBigNum(quantity));
            }
            multiAsset.insert(scriptHash, asset);
        }
        return multiAsset;
    }

    static buildTransactionMint(tokens: TokenWallet[], encoding: BufferEncoding = 'utf8'): Mint {
        let mint = Mint.new();
        const groups = tokens.reduce((dict: { [key: string]: TokenWallet[] }, asset: TokenWallet) => {
            (dict[asset.asset.policy_id] = dict[asset.asset.policy_id] || []).push(asset);
            return dict;
        }, {});
        for (const policy_id in groups) {
            const scriptHash = Seed.getScriptHashFromPolicy(policy_id);
            let mintAssets = MintAssets.new();
            const assetGroups = groups[policy_id].reduce((dict: { [key: string]: number }, asset: TokenWallet) => {
                dict[asset.asset.asset_name] = (dict[asset.asset.asset_name] || 0) + +asset.asset.quantity;
                return dict;
            }, {});
            for (const asset_name in assetGroups) {
                const quantity = assetGroups[asset_name];
                const assetName = AssetName.new(Buffer.from(asset_name, encoding));
                mintAssets.insert(assetName, quantity > 0 ? Int.new(toBigNum(quantity)) : Int.new_negative(toBigNum(Math.abs(quantity))));
            }
            mint.insert(scriptHash, mintAssets);
        }
        return mint;
    }

    static getTransactionFee(tx: Transaction, includeScripts: boolean, config = Mainnet) {
        const txFee = parseInt(min_fee(tx,
          LinearFee.new(BigNum.from_str(config.protocols.txFeePerByte.toString()), BigNum.from_str(config.protocols.txFeeFixed.toString()))).to_str());
        const scriptFee = includeScripts ? parseInt(min_script_fee(tx, ExUnitPrices.new(
          toUnitInterval(config.protocols.executionUnitPrices.priceMemory),
          toUnitInterval(config.protocols.executionUnitPrices.priceSteps)
        )).to_str()) : 0;
        return txFee + scriptFee;
      }

    static addKeyWitness(transaction: Transaction, prvKey: PrivateKey): Transaction {
        const vkeyWitnesses = Vkeywitnesses.new();
        const txBody = transaction.body();
        const txHash = hash_transaction(txBody);
        const vkeyWitness = make_vkey_witness(txHash, prvKey);
        vkeyWitnesses.add(vkeyWitness);
        const witnesses = transaction.witness_set();
        witnesses.set_vkeys(vkeyWitnesses);
        return Transaction.new(
            txBody,
            witnesses,
            transaction.auxiliary_data()
        );
    }

    static addScriptWitness(transaction: Transaction, script: NativeScript): Transaction {
        const txBody = transaction.body();
        const nativeScripts = NativeScripts.new();
        nativeScripts.add(script);
        const witnesses = transaction.witness_set();
        witnesses.set_native_scripts(nativeScripts);
        return Transaction.new(
            txBody,
            witnesses,
            transaction.auxiliary_data()
        );
    }

    static sign(txBody: TransactionBody, privateKeys: PrivateKey[], transactionMetadata?: AuxiliaryData, scripts?: (NativeScript | PlutusScript)[]): Transaction {
        const txHash = hash_transaction(txBody);
        const witnesses = TransactionWitnessSet.new();
        const vkeyWitnesses = Vkeywitnesses.new();
        if (privateKeys) {
            privateKeys.forEach(prvKey => {
                // add keyhash witnesses
                const vkeyWitness = make_vkey_witness(txHash, prvKey);
                vkeyWitnesses.add(vkeyWitness);
            });
        }
        witnesses.set_vkeys(vkeyWitnesses);
        if (scripts) {
            let nativeScripts = NativeScripts.new();
            scripts.forEach(s => {
                if (s instanceof NativeScript) {
                    nativeScripts.add(s);
                }
            });
            witnesses.set_native_scripts(nativeScripts);
        }

        const transaction = Transaction.new(
            txBody,
            witnesses,
            transactionMetadata
        );

        return transaction;
    }

    static signMessage(key: PrivateKey, message: string): string {
        return key.sign(Buffer.from(message)).to_hex();
    }

    static verifyMessage(key: PublicKey, message: string, signed: string): boolean {
        return key.verify(Buffer.from(message), Ed25519Signature.from_hex(signed));
    }

    static getTxId(transaction: Transaction): string {
        const txBody = transaction.body();
        const txHash = hash_transaction(txBody);
        const txId = txHash.to_hex();
        return txId;
    }

    static getFixedTxId(cborHex: string): string {
        const rawBody = FixedTransaction.from_hex(cborHex).raw_body();
        const txHash = TransactionHash.from_bytes(blake2b(32).update(rawBody).digest('binary'));
        return txHash.to_hex();
    }

    static convertPrivateKeyToSignKey(prkKey: Bip32PrivateKey): ExtendedSigningKey {
        // const k = Bip32PrivateKey.from_bech32(scriptKeys[1]);
        console.log(prkKey.to_bech32());
        // const hex = Buffer.from(prkKey.to_raw_key().as_bytes()).toString('hex');
        const cborHex = "5880" + Buffer.from(prkKey.to_128_xprv()).toString('hex');
        return new ExtendedSigningKey(cborHex);
        // console.log(hex);
    }

    static harden(num: number): number {
        return 0x80000000 + num;
    }

    static constructMetadata(data: any) {
        let metadata: any = {};

        if (Array.isArray(data)) {
            for (let i = 0; i < data.length; i++) {
                const value = data[i];
                metadata[i] = Seed.getMetadataObject(value);
            }
        } else {
            let keys = Object.keys(data);
            for (let i = 0; i < keys.length; i++) {
                const key = keys[i];
                if (this.isInteger(key)) {
                    let index = parseInt(key);
                    metadata[index] = Seed.getMetadataObject(data[key]);
                }
            }
        }
        return metadata;
    }

    static getMetadataObject(data: any) {
        let result: any = {};
        let type = typeof data;
        if (type == "number") {
            result[MetadateTypesEnum.Number] = data;
        } else if (type == "string" && Buffer.byteLength(data, 'utf-8') <= 64) {
            result[MetadateTypesEnum.String] = data;
        } else if (Buffer.isBuffer(data) && Buffer.byteLength(data, "hex") <= 64) {
            result[MetadateTypesEnum.Bytes] = data.toString("hex");
        } else if (type == "boolean") {
            result[MetadateTypesEnum.String] = data.toString();
        } else if (type == "undefined") {
            result[MetadateTypesEnum.String] = "undefined";
        } else if (Array.isArray(data)) {
            result[MetadateTypesEnum.List] = data.map(a => this.getMetadataObject(a));
        } else if (type == "object") {
            if (data) {
                result[MetadateTypesEnum.Map] = Object.keys(data).map(k => {
                    return {
                        "k": this.getMetadataObject(k),
                        "v": this.getMetadataObject(data[k])
                    }
                });
            } else {
                result[MetadateTypesEnum.String] = "null";
            }
        }
        return result;
    }

    static reverseMetadata(data: any, type = "object"): any {
        if (!data) {
            return null;
        }
        let metadata: any = type == "object" ? {} : [];
        let keys = Object.keys(data);
        for (let i = 0; i < keys.length; i++) {
            const key = keys[i];
            let index = parseInt(key);
            metadata[index] = Seed.reverseMetadataObject(data[key]);
        }
        return metadata;
    }

    static reverseMetadataObject(data: any): any {
        let result = [];
        let keys = Object.keys(data);
        for (let i = 0; i < keys.length; i++) {
            const key = keys[i];
            let value = data[key];
            if (key == "string") {
                result.push(value);
            } else if (key == "int") {
                result.push(new Number(value));
            } else if (key == "bytes") {
                result.push(Buffer.from(value, 'hex'));
            } else if (key == "list") {
                result.push(value.map((d: any) => Seed.reverseMetadataObject(d)))
            } else if (key == "map") {
                let map = value.reduce((acc: any, obj: any) => {
                    let k = Seed.reverseMetadataObject(obj["k"]);
                    let v = Seed.reverseMetadataObject(obj["v"]);
                    acc[k] = v;
                    return acc;
                }, {});
                result.push(map);
            } else {
                result.push(null);
            }
        }
        return result.length == 1 ? result[0] : result;
    }

    static buildPlutusData(data: any) {
        // const fields = PlutusList.new();
        // fields.add(PlutusData.new_bytes(Buffer.from('3f7826896a48c593598465a096d63606ceb8206', 'hex')));
        // fields.add(PlutusData.new_integer(BigInt.from_str("1888")));
        // fields.add(PlutusData.new_integer(BigInt.from_str("1")));
        // const constrDatum = ConstrPlutusData.new(
        // 	toBigNum(0),
        // 	fields
        // );
        // const datum = PlutusData.new_constr_plutus_data(constrDatum);
        // return datum;
        const result: any = {};
        const type = typeof data;
        if (type == 'number') {
            result['int'] = data;
        } else if (type == 'string') {
            result['bytes'] = Buffer.from(data).toString('hex');
        } else if (type == 'boolean') {
            result['string'] = data.toString();
        } else if (type == 'undefined') {
            result['string'] = 'undefined';
        } else if (Array.isArray(data)) {
            result['list'] = data.map((a) =>
                Seed.buildPlutusData(a),
            );
        } else if (type == 'object') {
            if (data) {
                result['map'] = Object.keys(data).map((k) => {
                    return {
                        k: Seed.buildPlutusData(k),
                        v: Seed.buildPlutusData(data[k]),
                    };
                });
            } else {
                result['string'] = 'null';
            }
        }
        return result;
    }

    static isPrintableUtf8(text: string, encoding: BufferEncoding = 'hex'): { utf8: boolean, text: string } {
        try {
            const t = Buffer.from(text, encoding).toString('utf8');
            return { utf8: !UNPRINTABLE_CHARACTERS_REGEXP.test(t), text: t };
        } catch (error) {
            return { utf8: false, text }
        }
    }

    static buildTransactionMetadata(data: any): AuxiliaryData {
        let metadata = Seed.constructMetadata(data);
        let generalMetatada = GeneralTransactionMetadata.new();
        for (const key in metadata) {
            let value = metadata[key];
            generalMetatada.insert(BigNum.from_str(key), Seed.getTransactionMetadatum(value));
        }
        let auxiliaryData = AuxiliaryData.new();
        auxiliaryData.set_metadata(generalMetatada);
        return auxiliaryData;
    }

    static buildCip68ReferenceAssetName(policy_id: string, asset_name: string): string {
        return CIP68_REFERENCE_PREFIX + asset_name.substring(8);
    }


    static getTransactionMetadatum(value: any): TransactionMetadatum {
        if (value.hasOwnProperty(MetadateTypesEnum.Number)) {
            return TransactionMetadatum.new_int(Int.new(toBigNum(value[MetadateTypesEnum.Number])));
        }
        if (value.hasOwnProperty(MetadateTypesEnum.String)) {
            return TransactionMetadatum.new_text(value[MetadateTypesEnum.String]);
        }
        if (value.hasOwnProperty(MetadateTypesEnum.Bytes)) {
            return TransactionMetadatum.new_bytes(Buffer.from(value[MetadateTypesEnum.Bytes], 'hex'));
        }
        if (value.hasOwnProperty(MetadateTypesEnum.List)) {
            let list = value[MetadateTypesEnum.List];
            let metalist = MetadataList.new();
            for (let i = 0; i < list.length; i++) {
                metalist.add(Seed.getTransactionMetadatum(list[i]));
            }
            return TransactionMetadatum.new_list(metalist);
        }
        if (value.hasOwnProperty(MetadateTypesEnum.Map)) {
            let map = value[MetadateTypesEnum.Map];
            let metamap = MetadataMap.new();
            for (let i = 0; i < map.length; i++) {
                let { k, v } = map[i];
                metamap.insert(Seed.getTransactionMetadatum(k), Seed.getTransactionMetadatum(v));
            }
            return TransactionMetadatum.new_map(metamap);
        }
        return TransactionMetadatum.new_int(Int.new(toBigNum(1)));
    }

    static generateKeyPair(): Bip32KeyPair {
        let prvKey = Bip32PrivateKey.generate_ed25519_bip32();
        let pubKey = prvKey.to_public();
        let pair: Bip32KeyPair = {
            privateKey: prvKey,
            publicKey: pubKey
        }

        return pair;
    }

    static generateBip32PrivateKey(): Bip32PrivateKey {
        return Bip32PrivateKey.generate_ed25519_bip32();
    }

    // enterprise address without staking ability, for use by exchanges/etc
    static getEnterpriseAddress(pubKey: Bip32PublicKey, network = 'mainnet'): Address {
        let networkId = network == 'mainnet' ? NetworkInfo.mainnet().network_id() : NetworkInfo.testnet_preprod().network_id();
        return EnterpriseAddress.new(networkId, StakeCredential.from_keyhash(pubKey.to_raw_key().hash())).to_address();
    }

    static getKeyHash(key: Bip32PublicKey): Ed25519KeyHash {
        return key.to_raw_key().hash();
    }

    static buildSingleIssuerScript(keyHash: Ed25519KeyHash): NativeScript {
        let scriptPubKey = ScriptPubkey.new(keyHash);
        return NativeScript.new_script_pubkey(scriptPubKey);
    }

    static buildMultiIssuerAllScript(scripts: NativeScript[]): NativeScript {
        let nativeScripts = this.buildNativeScripts(scripts);
        let scriptAll = ScriptAll.new(nativeScripts);
        return NativeScript.new_script_all(scriptAll);
    }

    static buildMultiIssuerAnyScript(scripts: NativeScript[]): NativeScript {
        let nativeScripts = this.buildNativeScripts(scripts);
        let scriptAny = ScriptAny.new(nativeScripts);
        return NativeScript.new_script_any(scriptAny);
    }

    static buildMultiIssuerAtLeastScript(n: number, scripts: NativeScript[]): NativeScript {
        let nativeScripts = this.buildNativeScripts(scripts);
        let scriptAtLeast = ScriptNOfK.new(n, nativeScripts);
        return NativeScript.new_script_n_of_k(scriptAtLeast);
    }

    // you need to set validity range on transcation builder to check on a deterministic way
    static buildAfterScript(slot: number): NativeScript {
        let scriptAfter = TimelockStart.new(slot);
        return NativeScript.new_timelock_start(scriptAfter);
    }

    // you need to set validity range on transcation builder to check on a deterministic way
    static buildBeforeScript(slot: number): NativeScript {
        let scriptBefore = TimelockExpiry.new(slot);
        return NativeScript.new_timelock_expiry(scriptBefore);
    }

    static getNativeScripts(script: Script): NativeScript[] {
        const result: NativeScript[] = [];
        const kind = script.root!.kind();
        if (kind == 0) { // sig
            result.push(script.root!)
        } else if (kind == 1 || kind == 2 || kind == 3) { // all, any and atLeast respectivetly
            result.push(...script.scripts.map(s => s.root!));
        }
        return result;
    }

    private static buildNativeScripts(scripts: NativeScript[]): NativeScripts {
        let nativeScripts = NativeScripts.new();
        scripts.forEach(script => {
            nativeScripts.add(script);
        });
        return nativeScripts;
    }

    static getScriptHash(script: NativeScript | PlutusScript): ScriptHash {
        let keyHash = script.hash();
        let scriptHash = ScriptHash.from_bytes(keyHash.to_bytes());
        return scriptHash;
        // let credential = StakeCredential.from_keyhash(keyHash);
        // return credential.to_scripthash();
    }

    static getPolicyId(scriptHash: ScriptHash): string {
        return Buffer.from(scriptHash.to_bytes()).toString('hex');
    }

    static getPolicyIdS(script: Script): string {
        const scriptHash = Seed.getScriptHash(script.root!);
        return Buffer.from(scriptHash.to_bytes()).toString('hex');
    }

    static getScriptHashFromPolicy(policyId: string): ScriptHash {
        return ScriptHash.from_bytes(Buffer.from(policyId, 'hex'));
    }

    static getMinUtxoValue(address: string | Address, config: any = Mainnet): number {
        const addr: Address = typeof address == 'string' ? Seed.getAddress(address) : address;
        const output = TransactionOutput.new(addr, Value.zero());
        const min = min_ada_for_output(output, Seed.getDataCost(config.protocols.utxoCostPerByte));
        return Number.parseInt(min.to_str());
    }

    static getMinUtxoValueWithAssets(address: string | Address, tokenAssets: AssetWallet[], datum: PlutusData | DataHash | null, scriptRef: ScriptRef | null, config: any = Mainnet, encoding: BufferEncoding = 'utf8'): number {
        let multiAsset = MultiAsset.new();
        const groups = tokenAssets.reduce((dict: { [key: string]: AssetWallet[] }, asset: AssetWallet) => {
            (dict[asset.policy_id] = dict[asset.policy_id] || []).push(asset);
            return dict;
        }, {});
        for (const policy_id in groups) {
            const scriptHash = Seed.getScriptHashFromPolicy(policy_id);
            let asset = Assets.new();
            groups[policy_id].forEach(a => {
                asset.insert(AssetName.new(Buffer.from(a.asset_name, encoding)), toBigNum(a.quantity));
            });
            multiAsset.insert(scriptHash, asset);
        }
        const addr: Address = typeof address == 'string' ? Seed.getAddress(address) : address;
        const value = Value.new_from_assets(multiAsset);
        const output = TransactionOutput.new(addr, value);
        if (datum) {
            (datum instanceof PlutusData) ? output.set_plutus_data(datum) : output.set_data_hash(datum);
        }
        if (scriptRef) {
            output.set_script_ref(scriptRef);
        }
        let min = min_ada_for_output(output, Seed.getDataCost(config.protocols.utxoCostPerByte));
        return Number.parseInt(min.to_str());
    }

    static getDataCost(utxoCostPerByte: number): DataCost {
        return DataCost.new_coins_per_byte(toBigNum(utxoCostPerByte));
    }

    // static buildMultisigJsonScript(type: ScriptTypeEnum, witnesses: number = 2): JsonScript {

    // 	if (lock) {
    // 		return {
    // 			type: ScriptTypeEnum.All,
    // 			scripts: [
    // 				{
    // 					type: ScriptTypeEnum.Sig
    // 				},
    // 				{
    // 					type: ScriptTypeEnum.Before,
    // 					lockTime: new Date(lockTime).getTime()
    // 				}
    // 			]
    // 		}
    // 	} else {
    // 		return {type: ScriptTypeEnum.Sig}
    // 	}
    // }

    // static getPrivateKey(key: string): PrivateKey {
    // 	if (key.startsWith('xprv1')) {
    // 		return Bip32PrivateKey.from_bech32(key).to_raw_key();
    // 	} else {
    // 		const unhex = Buffer.from(key, 'hex');
    // 		// const decode = cbor.decode(unhex);
    // 		try {
    // 			return PrivateKey.from_normal_bytes(decode);
    // 		} catch (err) {
    // 			return PrivateKey.from_extended_bytes(decode);
    // 		}
    // 	}
    // }

    static buildScript(json: JsonScript, currentSlot?: number): Script {
        if (json.type === ScriptTypeEnum.Sig) { // Single Issuer
            let keyPair: Bip32KeyPair | undefined = undefined; // needed to get the signing keys when export (e.g toJSON)
            let keyHash: Ed25519KeyHash;
            if (!json.keyHash) {
                keyPair = Seed.generateKeyPair();
                keyHash = Seed.getKeyHash(keyPair.publicKey);
            } else {
                keyHash = Ed25519KeyHash.from_bytes(Buffer.from(json.keyHash, 'hex'));
            }
            return { root: Seed.buildSingleIssuerScript(keyHash), keyHash: Buffer.from(keyHash.to_bytes()).toString('hex'), keyPair: keyPair, scripts: [] };
        }
        if (json.type === ScriptTypeEnum.All) { // Multiple Issuer All
            let scripts = json.scripts!.map(s => Seed.buildScript(s, currentSlot));
            return { root: Seed.buildMultiIssuerAllScript(scripts.map(s => s.root!)), scripts: scripts };
        }
        if (json.type === ScriptTypeEnum.Any) { // Multiple Issuer Any
            let scripts = json.scripts!.map(s => Seed.buildScript(s, currentSlot));
            return { root: Seed.buildMultiIssuerAnyScript(scripts.map(s => s.root!)), scripts: scripts };
        }
        if (json.type === ScriptTypeEnum.AtLeast) { // Multiple Issuer At least
            let scripts = json.scripts!.map(s => Seed.buildScript(s, currentSlot));
            let n = json.require!;
            return { root: Seed.buildMultiIssuerAtLeastScript(n, scripts.map(s => s.root!)), scripts: scripts };
        }
        if (json.type === ScriptTypeEnum.After) { // After
            let slot = 0;
            if (!json.slot) {
                slot = currentSlot!; // after now
                let lockTime = json.lockTime!;
                if (lockTime != 'now') {
                    let now = Date.now();
                    let datetime = new Date(lockTime).getTime();
                    slot = currentSlot! + Math.floor((datetime - now) / 1000);
                }
            } else {
                slot = json.slot;
            }
            return { root: Seed.buildAfterScript(slot), slot: slot, scripts: [] }
        }
        if (json.type === ScriptTypeEnum.Before) { // Before
            let slot = 0;
            if (!json.slot) {
                let lockTime = json.lockTime;
                slot = currentSlot! + 180; // only 3 min to mint tokens
                if (lockTime != 'now') {
                    let now = Date.now();
                    let datetime = new Date(lockTime!).getTime();
                    slot = currentSlot! + Math.floor((datetime - now) / 1000);
                }
            } else {
                slot = json.slot;
            }
            return { root: Seed.buildBeforeScript(slot), slot: slot, scripts: [] }
        }

        return { scripts: [] }
    }

    static scriptToJson(script: Script): any {
        let result: any = {};
        result.type = scriptTypes[script.root!.kind()];
        if (script.keyHash) {
            result.keyHash = script.keyHash;
        }
        if (result.type === 'atLeast') { // Multiple Issuer At least)
            result.require = script.root!.as_script_n_of_k()!.n();
        }
        if (result.type === 'after' || result.type === 'before') {
            result.slot = script.slot;
        }
        if (script.scripts && script.scripts.length > 0) {
            result.scripts = script.scripts.map(s => Seed.scriptToJson(s));
        }
        return result;
    }

    static getScriptKeys(script: Script): Bip32PrivateKey[] {
        let result: Bip32PrivateKey[] = [];
        if (script.keyPair) {
            // let prvKey = Bip32PrivateKey.from_bech32(script.signingKey);
            // let pubKey = prvKey.to_public();
            // result.push({ publicKey: pubKey, privateKey: prvKey});
            result.push(script.keyPair.privateKey);
        }
        script.scripts.forEach(s => {
            result.push(...Seed.getScriptKeys(s));
        })
        return result;
    }

    static getScriptAddress(script: Script, network = 'mainnet'): Address {
        let networkId = network == 'mainnet' ? NetworkInfo.mainnet().network_id() : NetworkInfo.testnet().network_id();
        const scriptHash = this.getScriptHash(script.root!);
        const credential = StakeCredential.from_scripthash(scriptHash);
        return BaseAddress.new(networkId, credential, credential).to_address();
    }

    static getPolicyScriptId(script: Script): string {
        let scriptHash = Seed.getScriptHash(script.root!);
        return Buffer.from(scriptHash.to_bytes()).toString('hex');
    }

    static findSlots(script: Script): { start?: number, end?: number } {
        let result: { start?: number, end?: number } = {};
        let type = script.root!.kind();
        if (type === 4) { //after
            result.start = script.slot;
        } else if (type === 5) { //before
            result.end = script.slot;
        } else {
            let slots = script.scripts.map(s => Seed.findSlots(s));
            result.start = slots.reduce((max, act) => !act.start && !max ? max : Math.max(act.start!, max!), result.start);
            result.end = slots.reduce((min, act) => !act.end ? min : !min ? act.end : Math.min(act.end, min), result.end);
        }
        return result;
    }

    static rebuildTransaction(partialTx: Transaction, multi: MultisigTransaction, witnessSet: TransactionWitnessSet): Transaction {
        const txBody = partialTx.body();

        const witnesses = partialTx.witness_set();
        const vkeyWitnesses = Vkeywitnesses.new();
        const currentkeys = witnesses.vkeys();
        if (currentkeys) {
            for (let i = 0; i < currentkeys.len(); i++) {
                const key = currentkeys.get(i);
                vkeyWitnesses.add(key);
            }
        }
        // const vkeyWitnesses = witnesses.vkeys();
        const keys = witnessSet.vkeys();
        if (keys) {
            const neededVKeys = multi.vkeys;
            if (neededVKeys) {
                for (let i = 0; i < keys.len(); i++) {
                    const key = keys.get(i);
                    if (neededVKeys[key.vkey().public_key().hash().to_bech32('vkey_')]) {
                        vkeyWitnesses.add(key);
                    }
                }
            }
        }
        // const nativeScripts = witnesses.native_scripts();

        if (vkeyWitnesses.len() > 0) {
            witnesses.set_vkeys(vkeyWitnesses);
        }
        // if (nativeScripts && nativeScripts.len() > 0) {
        // 	witnesses.set_native_scripts(nativeScripts);
        // }
        const tx = Transaction.new(txBody, witnesses, multi.metadata);
        return tx;
    }

    static signTx(txBody: TransactionBody, scripts: NativeScript[], privateKeys: PrivateKey[], metadata?: AuxiliaryData) {
        const witnessSet = TransactionWitnessSet.new();
        const witnesses = Vkeywitnesses.new();
        const txHash = hash_transaction(txBody);

        // private keys
        for (const prvKey of privateKeys) {
            const witness = make_vkey_witness(txHash, prvKey);
            witnesses.add(witness);
        }
        if (witnesses.len() > 0) {
            witnessSet.set_vkeys(witnesses);
        }

        // native scripts
        const nativeScripts = NativeScripts.new();
        for (const script of scripts) {
            nativeScripts.add(script);
        }
        if (nativeScripts.len() > 0) {
            witnessSet.set_native_scripts(nativeScripts);
        }

        const cloneMetadata = metadata ? AuxiliaryData.from_bytes(metadata.to_bytes()) : undefined;
        const tx = Transaction.new(
            txBody,
            witnessSet,
            cloneMetadata
        );
        return tx;
    }

    static buildPolicyScript(json: JsonScript, currentSlot: number): Script {
        if (json.type === ScriptTypeEnum.Sig) {
            // Single Issuer
            let keyPair: Bip32KeyPair | undefined; // needed to get the signing keys when export (e.g toJSON)
            let keyHash: Ed25519KeyHash;
            if (!json.keyHash) {
                keyPair = Seed.generateKeyPair();
                keyHash = Seed.getKeyHash(keyPair.publicKey);
            } else {
                keyHash = Ed25519KeyHash.from_bytes(Buffer.from(json.keyHash, 'hex'));
            }
            return {
                root: Seed.buildSingleIssuerScript(keyHash),
                keyHash: Buffer.from(keyHash.to_bytes()).toString('hex'),
                keyPair: keyPair,
                scripts: [],
            };
        }
        if (json.type === ScriptTypeEnum.All) {
            // Multiple Issuer All
            const scripts = json.scripts!.map((s) =>
                Seed.buildPolicyScript(s, currentSlot),
            );
            return {
                root: Seed.buildMultiIssuerAllScript(scripts.map((s) => s.root!)),
                scripts: scripts,
            };
        }
        if (json.type === ScriptTypeEnum.Any) {
            // Multiple Issuer Any
            const scripts = json.scripts!.map((s) =>
                Seed.buildPolicyScript(s, currentSlot),
            );
            return {
                root: Seed.buildMultiIssuerAnyScript(scripts.map((s) => s.root!)),
                scripts: scripts,
            };
        }
        if (json.type === ScriptTypeEnum.AtLeast) {
            // Multiple Issuer At least
            const scripts = json.scripts!.map((s) =>
                Seed.buildPolicyScript(s, currentSlot),
            );
            const n = json.require!;
            return {
                root: Seed.buildMultiIssuerAtLeastScript(
                    n,
                    scripts.map((s) => s.root!),
                ),
                scripts: scripts,
            };
        }
        if (json.type === ScriptTypeEnum.After) {
            // After
            let slot = 0;
            if (!json.slot) {
                slot = currentSlot; // after now
                const lockTime = json.lockTime!;
                if (lockTime != 'now') {
                    const now = Date.now();
                    const datetime = new Date(lockTime).getTime();
                    slot = currentSlot + Math.floor((datetime - now) / 1000);
                }
            } else {
                slot = json.slot;
            }
            return { root: Seed.buildAfterScript(slot), slot: slot, scripts: [] };
        }
        if (json.type === ScriptTypeEnum.Before) {
            // Before
            let slot = 0;
            if (!json.slot) {
                const lockTime = json.lockTime!;
                slot = currentSlot + 180; // only 3 min to mint tokens
                if (lockTime != 'now') {
                    const now = Date.now();
                    const datetime = new Date(lockTime).getTime();
                    slot = currentSlot + Math.floor((datetime - now) / 1000);
                }
            } else {
                slot = json.slot;
            }
            return { root: Seed.buildBeforeScript(slot), slot: slot, scripts: [] };
        }

        return { scripts: [] }
    }

    static txUnspentOutputToCoinSelectionInput(txOut: TransactionUnspentOutput): ApiCoinSelectionInputs {
        const input = txOut.input();
        const output = txOut.output();
        const amount = output.amount();
        const total = parseInt(amount.coin().to_str());
        const address = output.address().to_bech32();
        const hash = input.transaction_id().to_hex();
        const index = input.index();
        const multiasset = amount.multiasset();
        const assets: {
            policy_id: string;
            asset_name: string;
            quantity: number
        }[] = [];
        // get all input assets
        if (multiasset && multiasset.len() > 0) {
            const assetKeys = multiasset.keys();
            for (let i = 0; i < assetKeys.len(); i++) {
                const scriptHash = assetKeys.get(i);
                const policyId = Buffer.from(scriptHash.to_bytes()).toString('hex');
                const asset = multiasset.get(scriptHash)!;
                const assetNames = asset.keys();
                for (let j = 0; j < assetNames.len(); j++) {
                    const assetName = assetNames.get(j);
                    const name = Buffer.from(assetName.name()).toString('hex');
                    const quantity = parseInt(asset.get(assetName)!.to_str());
                    assets.push({
                        policy_id: policyId,
                        asset_name: name,
                        quantity: quantity
                    })
                }
            }
        }
        return {
            "amount": {
                "quantity": total,
                "unit": WalletswalletIdpaymentfeesAmountUnitEnum.Lovelace
            },
            "address": address,
            "id": hash,
            "assets": assets,
            "index": index
        }
    }

    static cborEncodeAmount(amount: any) {
        if (Array.isArray(amount)) { // format [ada, assets]
            const [ada, assets] = amount;
            // const multiassets = this.buildMultiAssets(assets);
            return Value.from_json(JSON.stringify({
                coin: Number(ada).toString(),
                multiasset: Object.entries<any>(assets).reduce((dict, [policy_id, tokens]) => ({ ...dict, [policy_id]: Object.entries<any>(tokens).reduce((d, [asset_name, quantity]) => ({ ...d, [asset_name]: quantity.toString() }), {}) }), {})
            })).to_hex();
        } else {
            return Value.new(toBigNum(amount)).to_hex();
        }
    }

    static fakePrivateKey(): Bip32PrivateKey {
        return Bip32PrivateKey.from_bytes(
            Buffer.from([0xb8, 0xf2, 0xbe, 0xce, 0x9b, 0xdf, 0xe2, 0xb0, 0x28, 0x2f, 0x5b, 0xad, 0x70, 0x55, 0x62, 0xac, 0x99, 0x6e, 0xfb, 0x6a, 0xf9, 0x6b, 0x64, 0x8f,
                0x44, 0x45, 0xec, 0x44, 0xf4, 0x7a, 0xd9, 0x5c, 0x10, 0xe3, 0xd7, 0x2f, 0x26, 0xed, 0x07, 0x54, 0x22, 0xa3, 0x6e, 0xd8, 0x58, 0x5c, 0x74, 0x5a,
                0x0e, 0x11, 0x50, 0xbc, 0xce, 0xba, 0x23, 0x57, 0xd0, 0x58, 0x63, 0x69, 0x91, 0xf3, 0x8a, 0x37, 0x91, 0xe2, 0x48, 0xde, 0x50, 0x9c, 0x07, 0x0d,
                0x81, 0x2a, 0xb2, 0xfd, 0xa5, 0x78, 0x60, 0xac, 0x87, 0x6b, 0xc4, 0x89, 0x19, 0x2c, 0x1e, 0xf4, 0xce, 0x25, 0x3c, 0x19, 0x7e, 0xe2, 0x19, 0xa4]
            )
        );
    }

    static getStakeAddress(address: string): string | null {
        try {

            const addr = Address.from_bech32(address);
            const baseAddr = BaseAddress.from_address(addr);
            let stakeAddr = null;
            if (baseAddr) {
                const stakeCredential = baseAddr.stake_cred();
                const reward = RewardAddress.new(addr.network_id(), stakeCredential);
                stakeAddr = reward.to_address().to_bech32();
            }
            return stakeAddr;
        } catch (err) {
            return null;
        }
    }

    private static isInteger(value: any) {
        return Number.isInteger(Number(value));
    }

}

export function toBigNum(quantity: number): BigNum {
    return BigNum.from_str(quantity.toString());
}

export function toUnitInterval(decimal: number) {
    const decimalStr = decimal.toString();
    const index = decimalStr.indexOf(".") + 1;
    const decimals = index ? decimalStr.length - index : 0;
    const denominator = Math.pow(10, decimals);
    const numerator = decimal * denominator;
    return UnitInterval.new(toBigNum(numerator), toBigNum(denominator));
}

export declare type Bip32KeyPair = {
    privateKey: Bip32PrivateKey;
    publicKey: Bip32PublicKey;
}

export enum MetadateTypesEnum {
    Number = "int",
    String = "string",
    Bytes = "bytes",
    List = "list",
    Map = "map",
}

export const CARDANO_PUROPOSE = 1852;
export const CARDANO_COIN_TYPE = 1815;
export const CARDANO_EXTERNAL = 0;
export const CARDANO_CHANGE = 1;
export const CARDANO_CHIMERIC = 2;
