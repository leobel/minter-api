import { Address, AuxiliaryData, BigNum, Bip32PrivateKey, DataHash, hash_auxiliary_data, hash_plutus_data, hash_transaction, LinearFee, make_vkey_witness, min_fee, min_script_fee, NativeScript, NativeScripts, PlutusData, PlutusList, PrivateKey, Transaction, TransactionBody, TransactionHash, TransactionOutput, TransactionOutputs, TransactionWitnessSet, Value, Vkey, Vkeywitness, Vkeywitnesses, PlutusScripts, Redeemers, TxBuilderConstants, hash_script_data, ExUnitPrices, UnitInterval, ScriptRef, TransactionInput } from "@emurgo/cardano-serialization-lib-nodejs";
import { Seed, toUnitInterval } from "../utils";
import { CoinSelectionWallet } from "../wallet/coin-selection-wallet";
import { TokenWallet } from "../wallet/token-wallet";
import { WalletswalletIdpaymentfeesPayments } from "./walletswallet-idpaymentfees-payments";
import { ApiCoinSelectionChange } from "./api-coin-selection-change";

export class MultisigTransaction {
    txBody!: TransactionBody;
    vkeyWitnesses: Vkeywitnesses;
    nativeScripts: NativeScripts;
    metadata?: AuxiliaryData;
    txHash!: TransactionHash;
    vkeys!: { [key: string]: number };
    plutusData: PlutusList;
    plutusScripts: PlutusScripts;
    redeemers: Redeemers;
    constructor() {
        this.vkeyWitnesses = Vkeywitnesses.new();
        this.nativeScripts = NativeScripts.new();
        this.plutusData = PlutusList.new();
        this.plutusScripts = PlutusScripts.new();
        this.redeemers = Redeemers.new();
    }

    static new(
        total: number,
        outputs: WalletswalletIdpaymentfeesPayments[],
        change: ApiCoinSelectionChange[],
        txBody: TransactionBody,
        scripts: NativeScript[],
        plutusScripts: PlutusScripts,
        redeemers: Redeemers,
        plutusData: PlutusList,
        collateral: { amount: Value, input: TransactionInput, address: Address }[],
        privateKeys: PrivateKey[],
        vkeys: { [key: string]: number },
        config: any,
        encoding: BufferEncoding,
        metadata?: AuxiliaryData,
        assets?: TokenWallet[]
    ): MultisigTransaction {
        const multisig = new MultisigTransaction();
        multisig.metadata = metadata;
        multisig.vkeys = vkeys;

        multisig.plutusData = plutusData;
        multisig.plutusScripts = plutusScripts;
        multisig.redeemers = redeemers;

        scripts.forEach(s => {
            multisig.nativeScripts.add(s);
        });

        const numberOfWitnesses = Object.values(vkeys).reduce((total, cur) => total + cur, 0);
        multisig.txBody = multisig.adjustFee(total, txBody, collateral, outputs, change, assets!, numberOfWitnesses, config, encoding);
        multisig.txHash = hash_transaction(multisig.txBody);

        privateKeys.forEach(prvKey => {
            // add keyhash witnesses
            const vkeyWitness = make_vkey_witness(multisig.txHash, prvKey);
            multisig.vkeyWitnesses.add(vkeyWitness);
        });
        return multisig;
    }

    addKeyWitnesses(...privateKeys: PrivateKey[]): void {
        privateKeys.forEach(prvKey => {
            // add keyhash witnesses
            const vkeyWitness = make_vkey_witness(this.txHash, prvKey);
            this.vkeyWitnesses.add(vkeyWitness);
        });
    }

    addKeyWitnessesRaw(...witnesses: Vkeywitness[]): void {
        witnesses.forEach(vkeyWitness => {
            this.vkeyWitnesses.add(vkeyWitness);
        });
    }

    // cannot add script witnesses after adjusting fee
    addScriptWitness(...scripts: NativeScript[]): void {
        scripts.forEach(s => {
            this.nativeScripts.add(s);
        });
    }

    adjustFee(total: number, txBody: TransactionBody, collateralCandidates: { amount: Value, input: TransactionInput, address: Address }[], outputs: WalletswalletIdpaymentfeesPayments[], changes: ApiCoinSelectionChange[], assets: TokenWallet[], numberOfWitnesses: number, config: any, encoding: BufferEncoding): TransactionBody {
        const bodyFee = parseInt(txBody.fee().to_str());
        let txFee = this.fakeTx(txBody, collateralCandidates, numberOfWitnesses, config);

        // console.log(`Fees: initial = ${bodyFee}, adjusted = ${txFee}`);
        if (txFee > bodyFee && this.redeemers.len() == 0) { // tx size is simple too big
            throw new Error("Tx too big");
        }
        if (txFee != bodyFee) {
            let txCost = 0;
            let outs: any[] = [];
            if (changes.length > 0) {
                const feeDiffPerChange = Math.floor(txFee / changes.length);
                // console.log('Each change decrease their revenue by:', feeDiffPerChange);
                outs = changes.map(ch => {
                    const address = Seed.getAddress(ch.address);
                    const quantity = ch.amount.quantity - feeDiffPerChange;
                    if (quantity < 0) {
                        throw new Error('not enough funds');
                    }
                    if (quantity < Seed.getMinUtxoValue(address, config)) {
                        return null;
                    }
                    txCost += quantity;
                    let amount = Value.new(
                        BigNum.from_str(quantity.toString())
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
                        Seed.addPlutusData(ch, utxo);
                    }

                    // add script_ref
                    if (ch.script_ref) {
                        utxo.set_script_ref(ScriptRef.from_hex(ch.script_ref));
                    }

                    return utxo;
                }).filter(c => !!c);
            }
            // console.log('Outputs:', JSON.stringify(outputs));
            // console.log('Changes:', JSON.stringify(changes));
            outs.push(...outputs.map(output => {
                let address = Seed.getAddress(output.address);
                const quantity = +output.amount.quantity;
                txCost += quantity;
                let amount = Value.new(
                    BigNum.from_str(quantity.toString())
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
                    Seed.addPlutusData(output, utxo);
                }

                // add script_ref
                if (output.script_ref) {
                    utxo.set_script_ref(ScriptRef.from_hex(output.script_ref));
                }

                return utxo;
            }));

            const remaining = total - txCost - txFee;
            if (remaining > 0) {
                txFee += remaining; // avoid ValueNotConservedUTxO, so add remaining to fee;
                // console.log(`There is remaining (add to final fee): ${remaining}`);
            }
            const txOutputs = TransactionOutputs.new();
            outs.forEach(txout => txOutputs.add(txout));
            const body = TransactionBody.new(txBody.inputs(), txOutputs, BigNum.from_str(txFee.toString()), txBody.ttl());

            // metadata
            if (this.metadata) {
                const dataHash = hash_auxiliary_data(this.metadata);
                body.set_auxiliary_data_hash(dataHash);
            }
            // mint tokens
            if (assets) {
                const mint = Seed.buildTransactionMint(assets, encoding);
                body.set_mint(mint);
            }

            if (txBody.collateral()) { // adjust collateral
                const { inputs, output } = Seed.buildCollateral(collateralCandidates, Math.ceil(txFee * config.protocols.collateralPercentage / 100), config);
                body.set_collateral(inputs);
                if (output) {
                    body.set_collateral_return(output);
                }
            }

            if (txBody.required_signers()) {
                body.set_required_signers(txBody.required_signers()!);
            }

            if (txBody.reference_inputs()) {
                body.set_reference_inputs(txBody.reference_inputs()!);
            }

            const scriptDataHash = txBody.script_data_hash();
            if (scriptDataHash) {
                body.set_script_data_hash(scriptDataHash);
            }

            // set tx validity start interval
            const startInterval = txBody.validity_start_interval();
            if (startInterval) {
                body.set_validity_start_interval(startInterval);
            }

            return body;
        } else {
            return txBody;
        }
    }

    build(includePlutusData = true): string {
        const witnesses = TransactionWitnessSet.new();
        witnesses.set_vkeys(this.vkeyWitnesses);
        if (this.nativeScripts.len() > 0) {
            witnesses.set_native_scripts(this.nativeScripts);
        }

        // only skeep the plutusData from witness set and metadata to not reveal any NFT info
        if (includePlutusData && this.plutusData.len() > 0) {
            witnesses.set_plutus_data(this.plutusData);
        }

        if (this.plutusScripts.len() > 0) {
            witnesses.set_plutus_scripts(this.plutusScripts);
        }

        if (this.redeemers.len() > 0) {
            witnesses.set_redeemers(this.redeemers);
        }

        const tx = Transaction.new(
            this.txBody,
            witnesses
        );

        tx.body().collateral()

        return Buffer.from(tx.to_bytes()).toString('hex');
    }

    toBytes(): Uint8Array {
        const encoder = new TextEncoder();
        const data = this.toJSON();
        return encoder.encode(JSON.stringify(data));
    }

    toString(): string {
        const data = this.toJSON();
        return JSON.stringify(data);
    }

    static fromBytes(bytes: Uint8Array): MultisigTransaction {
        const decoder = new TextDecoder();
        const text = decoder.decode(bytes);
        return MultisigTransaction.fromJSON(text);
    }

    static fromString(text: string): MultisigTransaction {
        return MultisigTransaction.fromJSON(text);
    }

    private toJSON(): any {
        const keys = Array.from(Array(this.vkeyWitnesses.len()).keys()).map(i => this.vkeyWitnesses.get(i).to_bytes()).map(k => Buffer.from(k).toString('hex'));
        const scripts = Array.from(Array(this.nativeScripts.len()).keys()).map(i => this.nativeScripts.get(i).to_bytes()).map(s => Buffer.from(s).toString('hex'));
        const json = {
            body: Buffer.from(this.txBody.to_bytes()).toString('hex'),
            keys: keys,
            scripts: scripts,
            metadata: this.metadata ? Buffer.from(this.metadata.to_bytes()).toString('hex') : null,
            vkeys: Buffer.from(JSON.stringify(this.vkeys)).toString('hex'),
            datums: this.plutusData.to_hex(),
            plutus_scripts: this.plutusScripts.to_hex(),
            redeemers: this.redeemers.to_hex()
        }
        return json;
    }

    private static fromJSON(text: string) {
        const { body, keys, scripts, metadata, vkeys, datums, plutus_scripts, redeemers } = JSON.parse(text);
        const multisig = new MultisigTransaction();
        multisig.txBody = TransactionBody.from_bytes(Buffer.from(body, 'hex'));
        multisig.txHash = hash_transaction(multisig.txBody);
        multisig.metadata = metadata ? AuxiliaryData.from_bytes(Buffer.from(metadata, 'hex')) : undefined;
        const vKyes: Vkeywitness[] = keys.map((k: any) => Vkeywitness.from_bytes(Buffer.from(k, 'hex')));
        for (const key of vKyes) {
            multisig.vkeyWitnesses.add(key);
        }
        const nScripts: NativeScript[] = scripts.map((k: any) => NativeScript.from_bytes(Buffer.from(k, 'hex')));
        for (const script of nScripts) {
            multisig.nativeScripts.add(script);
        }
        multisig.vkeys = JSON.parse(Buffer.from(vkeys, 'hex').toString());
        multisig.plutusData = PlutusList.from_hex(datums);
        multisig.plutusScripts = PlutusScripts.from_hex(plutus_scripts);
        multisig.redeemers = Redeemers.from_hex(redeemers);
        return multisig;
    }

    private fakeTx(txBody: TransactionBody, collateralCandidates: { amount: Value, input: TransactionInput, address: Address }[], numberOfWitnesses: number, config: any) {
        const fakeWitnesses = Vkeywitnesses.new();
        const fakeKey = this.fakePrivateKey();
        const rawKey = fakeKey.to_raw_key();
        // const txHash = hash_transaction(txBody).to_bytes();
        const fakeVkeyWitness = Vkeywitness.new(
            Vkey.new(rawKey.to_public()),
            // rawKey.sign(txHash)
            rawKey.sign(Buffer.from(Array.from(Array(100).keys())))
        );
        for (let i = 0; i < numberOfWitnesses; i++) {
            fakeWitnesses.add(fakeVkeyWitness);
        }

        const witnessSet = TransactionWitnessSet.new();
        witnessSet.set_vkeys(fakeWitnesses);
        if (this.nativeScripts.len() > 0) {
            witnessSet.set_native_scripts(this.nativeScripts);
        }

        if (this.plutusData.len() > 0) {
            witnessSet.set_plutus_data(this.plutusData);
        }

        if (this.plutusScripts.len() > 0) {
            witnessSet.set_plutus_scripts(this.plutusScripts);
        }

        if (this.redeemers.len() > 0) {
            witnessSet.set_redeemers(this.redeemers);
        }

        const cloneMetadata = this.metadata ? AuxiliaryData.from_bytes(this.metadata.to_bytes()) : undefined;
        let tx = Transaction.new(
            txBody,
            witnessSet,
            cloneMetadata
        );
        let txFee = Seed.getTransactionFee(tx, this.redeemers.len() > 0, config);
        return txFee;
    }

    private fakePrivateKey(): Bip32PrivateKey {
        return Bip32PrivateKey.from_bytes(
            Buffer.from([0xb8, 0xf2, 0xbe, 0xce, 0x9b, 0xdf, 0xe2, 0xb0, 0x28, 0x2f, 0x5b, 0xad, 0x70, 0x55, 0x62, 0xac, 0x99, 0x6e, 0xfb, 0x6a, 0xf9, 0x6b, 0x64, 0x8f,
                0x44, 0x45, 0xec, 0x44, 0xf4, 0x7a, 0xd9, 0x5c, 0x10, 0xe3, 0xd7, 0x2f, 0x26, 0xed, 0x07, 0x54, 0x22, 0xa3, 0x6e, 0xd8, 0x58, 0x5c, 0x74, 0x5a,
                0x0e, 0x11, 0x50, 0xbc, 0xce, 0xba, 0x23, 0x57, 0xd0, 0x58, 0x63, 0x69, 0x91, 0xf3, 0x8a, 0x37, 0x91, 0xe2, 0x48, 0xde, 0x50, 0x9c, 0x07, 0x0d,
                0x81, 0x2a, 0xb2, 0xfd, 0xa5, 0x78, 0x60, 0xac, 0x87, 0x6b, 0xc4, 0x89, 0x19, 0x2c, 0x1e, 0xf4, 0xce, 0x25, 0x3c, 0x19, 0x7e, 0xe2, 0x19, 0xa4]
            )
        );
    }
}