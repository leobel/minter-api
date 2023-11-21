import * as crypto from 'crypto';
import axios from 'axios';
import { ExUnits, Transaction, TransactionUnspentOutput, TransactionWitnessSet, Vkeywitnesses } from '@emurgo/cardano-serialization-lib-nodejs';
import { Seed, toBigNum } from '../utils';
import { SignTxData } from '../models/sign-tx.dto';
import { MultisigTransaction } from '../models/multisig-transaction';
import { AssetWallet } from '../wallet/asset-wallet';
import { WalletswalletIdpaymentfeesAmountUnitEnum, WalletswalletIdpaymentfeesPayments } from '../models';

const algorithm = 'aes-256-ctr';
const iv = Buffer.from('47f0e92dd0fda4efca200016ef0f0b27', 'hex');

export async function getExUnits(url: string, key: string, tx: string, type = 'mint'): Promise<ExUnits> {
    // adjust redeemer exUnits
    const exUnitsResponse = await axios.post(`${url}/utils/txs/evaluate`, tx, {
        headers: {
            'Content-Type': 'application/cbor',
            'Accept': 'application/json',
            'project_id': key
        }
    });
    console.log(JSON.stringify(exUnitsResponse.data.result, null, 2));
    if (exUnitsResponse.data.result['EvaluationFailure']) {
        throw new Error(exUnitsResponse.data.result['EvaluationFailure']);
    }

    console.log('ExUnits:', exUnitsResponse.data.result);
    const units = Object.entries<any>(exUnitsResponse.data.result.EvaluationResult).filter(([tag]) => tag.startsWith(type));
    let maxMemory = -1;
    let maxSteps = -1;
    for (const [_, { memory, steps }] of units) {
        if (memory > maxMemory) {
            maxMemory = memory;
        }
        if (steps > maxSteps) {
            maxSteps = steps;
        }
    }
    return ExUnits.new(toBigNum(Math.floor(maxMemory * 1.1)), toBigNum(Math.floor(maxSteps * 1.1)));

}

export async function getLatestBlock(url: string, key: string): Promise<number> {
    const response = await axios.get(`${url}/blocks/latest`, {
        headers: {
            'project_id': key
        }
    });

    return response.data.slot;
}

export async function getRefenceTokenInfo(url: string, key: string, asset: string): Promise<{tx_hash: string, index: number, amount: { quantity: number, unit: WalletswalletIdpaymentfeesAmountUnitEnum }, datum: string}> {
    // get last transaction
    let response = await axios.get(`${url}/assets/${asset}/transactions`, {
        headers: {
            'project_id': key
        }
    });
    const txs = response.data;
    const [tx] = txs.sort((a: any, b: any) => b.block_height - a.block_height);
    const tx_hash = tx.tx_hash;
    
    // get transaction utxos
    response = await axios.get(`${url}/txs/${tx_hash}/utxos`, {
        headers: {
            'project_id': key
        }
    });

    const utxos = response.data.outputs;
    const utxo = utxos.find((tx: any) => tx.amount.some((a: any) => a.unit == asset));
    const index = utxo.output_index;
    const amount = utxo.amount.find((a: any) => a.unit == WalletswalletIdpaymentfeesAmountUnitEnum.Lovelace);

    // get datum cbor
    response = await axios.get(`${url}/scripts/datum/${utxo.data_hash}/cbor`, {
        headers: {
            'project_id': key
        }
    });

    const datum = response.data.cbor;

    return { tx_hash, index, amount, datum };
}

export function signTx(data: SignTxData) {
    const { tx, signatures, multi } = data;
    const unsignedTx = Transaction.from_hex(tx);
    const keys = new Set();
    const witnesses = signatures.reduce((ws, signature) => {
        const s = TransactionWitnessSet.from_bytes(Buffer.from(signature, 'hex'));
        const vkeys = s.vkeys();
        if (vkeys) {
            for (let i = 0; i < vkeys.len(); i++) {
                const key = vkeys.get(i);
                const hash = key.vkey().public_key().hash().to_hex();
                if (!keys.has(hash)) {
                    keys.add(hash);
                    ws.add(key);
                }
            }
        }
        return ws;
    }, Vkeywitnesses.new());

    const witnessSet = TransactionWitnessSet.new();
    witnessSet.set_vkeys(witnesses)
    const encryptKey = process.env.ENCRYPT_KEY!;
    const multisig = MultisigTransaction.fromString(decrypt(encryptKey, multi));
    const { tx: signTx, isValid } = rebuildTransaction(unsignedTx, multisig, witnessSet);
    return isValid ? Buffer.from(signTx!.to_bytes()).toString('hex') : null;
}

export function calculateInputs(inputs: TransactionUnspentOutput[], network: any) {
    let total = 0;
    let remaining = 0;
    const outputs: WalletswalletIdpaymentfeesPayments[] = [];
    // buyer assets that where sent to us
    for (let i = 0; i < inputs.length; i++) {
        const input = inputs[i];
        const multiasset = input.output().amount().multiasset();
        const amount = parseInt(input.output().amount().coin().to_str());
        remaining += amount;
        total += amount;
        if (!multiasset || multiasset.len() == 0) {
            continue;
        }
        const inputAssets: AssetWallet[] = [];
        const assetKeys = multiasset.keys();
        // get all input assets
        for (let i = 0; i < assetKeys.len(); i++) {
            const scriptHash = assetKeys.get(i);
            const policyId = Buffer.from(scriptHash.to_bytes()).toString('hex')
            const assets = multiasset.get(scriptHash)!;
            const assetNames = assets.keys();
            const dict: { [key: string]: number } = {};
            for (let j = 0; j < assetNames.len(); j++) {
                const assetName = assetNames.get(j);
                const name = Buffer.from(assetName.name()).toString('hex');
                const quantity = parseInt(assets.get(assetName)!.to_str());
                dict[name] = (dict[name] || 0) + quantity;
            }
            inputAssets.push(...Object.keys(dict).map(name => ({
                policy_id: policyId,
                asset_name: name,
                quantity: dict[name]
            })));
        }

        // add previuos tokens utxo
        if (inputAssets.length > 0) {
            const inputAddr = input.output().address();
            const minAda = Seed.getMinUtxoValueWithAssets(inputAddr, inputAssets, null, null, network, 'hex');
            remaining -= minAda;
            outputs.push({
                address: inputAddr.to_bech32(),
                amount: {
                    quantity: minAda,
                    unit: WalletswalletIdpaymentfeesAmountUnitEnum.Lovelace,
                },
                assets: inputAssets,
            });
        }
    }

    return { total, remaining, outputs };
}

export function sortInputs(inputs: TransactionUnspentOutput[]): TransactionUnspentOutput[] {
    return inputs.sort((a, b) => {
        const aInput = a.input();
        const bInput = b.input();
        const aId = aInput.transaction_id().to_hex();
        const bId = bInput.transaction_id().to_hex();
        const aIndex = aInput.index();
        const bIndex = bInput.index();
        return aId != bId ? aId < bId ? -1 : 1 : aIndex - bIndex;
    });
}

export function getMaxExUnits(network: any) {
    const { memory, steps } = network.protocols.maxTxExecutionUnits;
    return ExUnits.new(toBigNum(memory), toBigNum(steps));
}

export function rebuildTransaction(partialTx: Transaction, multi: MultisigTransaction, witnessSet: TransactionWitnessSet): { tx?: Transaction, isValid: boolean } {
    const witnesses = partialTx.witness_set();
    const vkeyWitnesses = Vkeywitnesses.new();
    const walletKeys = witnessSet.vkeys();
    const data = partialTx.auxiliary_data();
    const plutusData = witnesses.plutus_data();
    const neededVKeys = multi.vkeys;

    let numberOfWitnesses = neededVKeys.size;

    // add previous witnesses keys coming from the sale, e.g policy script keys
    const nativeScripts = witnesses.native_scripts();
    const currentkeys = witnesses.vkeys();
    const currentKeyHashes = new Set<string>();
    if (currentkeys) {
        for (let i = 0; i < currentkeys.len(); i++) {
            const key = currentkeys.get(i);
            const keyHash = key.vkey().public_key().hash().to_hex();
            if (!currentKeyHashes.has(keyHash)) {
                vkeyWitnesses.add(key);
                currentKeyHashes.add(keyHash);
            }
        }
    }

    // add wallet witnesses keys
    if (walletKeys) {
        for (let i = 0; i < walletKeys.len(); i++) {
            const key = walletKeys.get(i);
            const keyHash = key.vkey().public_key().hash().to_hex();
            if (neededVKeys[keyHash] && !currentKeyHashes.has(keyHash)) {
                vkeyWitnesses.add(key);
                currentKeyHashes.add(keyHash);
            }
        }
    }

    if (vkeyWitnesses.len() > 0) {
        witnesses.set_vkeys(vkeyWitnesses);
    }
    if (nativeScripts && nativeScripts.len() > 0) {
        witnesses.set_native_scripts(nativeScripts);
    }

    if (numberOfWitnesses != currentKeyHashes.size) {
        // console.log('Invalid wallet witnesses, expected vs final witnesses:', numberOfWitnesses, finalWitnesses);
        return { isValid: false }
    }

    if (plutusData && plutusData.len() > 0) {
        witnesses.set_plutus_data(plutusData);
    }

    const tx = Transaction.new(partialTx.body(), witnesses, data);

    return { tx, isValid: true };
}

export function encrypt(secretKey: string, text: crypto.BinaryLike, encoding: BufferEncoding = 'hex'): string {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return encrypted.toString(encoding);
}

export function decrypt(
    secretKey: string,
    ciphertext:
        | WithImplicitCoercion<string>
        | { [Symbol.toPrimitive](hint: 'string'): string },
    encoding: BufferEncoding = 'hex'
): string {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    const decrpyted = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, encoding)),
        decipher.final(),
    ]);
    return decrpyted.toString();
}