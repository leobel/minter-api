import axios from 'axios';
import { Ed25519KeyHash, ExUnits, NativeScript, PlutusScript, PrivateKey, RedeemerTag, Transaction, TransactionBody, TransactionHash, TransactionInput, TransactionUnspentOutput, TransactionWitnessSet, Vkeywitnesses } from "@emurgo/cardano-serialization-lib-nodejs";
import { BuildTxData } from "../models/build-tx.dto";
import { CIP68_RNFT_PREFIX, Seed, toBigNum } from "../utils";
import { CoinSelectionWallet } from "../wallet/coin-selection-wallet";
import { Mainnet, Testnet } from "../config/network.config";
import { TokenWallet } from "../wallet/token-wallet";
import { AssetWallet } from "../wallet/asset-wallet";
import { ApiCoinSelectionChange, WalletswalletIdpaymentfeesAmountUnitEnum, WalletswalletIdpaymentfeesPayments } from "../models";
import { SignTxData } from '../models/sign-tx.dto';
import * as crypto from 'crypto';
import { MultisigTransaction } from '../models/multisig-transaction';
const algorithm = 'aes-256-ctr';
const iv = Buffer.from('47f0e92dd0fda4efca200016ef0f0b27', 'hex');

export async function buildTx(data: BuildTxData) {
    const { script, tokens: tTokens, payments, collaterals, change_address } = data;
    const network = script.reference_address.startsWith('addr_test') ? 'preprod' : 'mainnet';

    const policyId = script.policy_id;
    const tokens = Object.entries(tTokens).flatMap(([address, tokens]) => tokens.map(data => ({
        ...data,
        cip68_version: 1,
        receiverAddress: address,
    })));
    const configNetwork = network == 'mainnet' ? Mainnet : Testnet;
    const blockfrostKey = process.env.BLOCKFROST_KEY;
    const blockfrostUrl = network == 'mainnet' ? 'https://cardano-mainnet.blockfrost.io/api/v0' : 'https://cardano-preprod.blockfrost.io/api/v0';

    // get inputs
    const inputs = payments.map(d => TransactionUnspentOutput.from_bytes(Buffer.from(d, 'hex')));

    // get outputs
    const outputs: WalletswalletIdpaymentfeesPayments[] = [];

    // get change
    const change: ApiCoinSelectionChange[] = [];

    // get collaterals
    const collateral = collaterals.map(c => TransactionUnspentOutput.from_bytes(Buffer.from(c, 'hex')));

    const signingKeys: PrivateKey[] = [];

    const requirePolicyKeys = script.signers.map(s => Ed25519KeyHash.from_hex(s));

    const scripts: NativeScript[] = [];

    let total = 0;
    let remaining = 0;
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
            const minAda = Seed.getMinUtxoValueWithAssets(inputAddr, inputAssets, null, null, configNetwork, 'hex');
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

    // plutus script section 
    const plutusScript = PlutusScript.from_bytes_v2(Buffer.from(script.mint, 'hex'));
    const { memory, steps } = configNetwork.protocols.maxTxExecutionUnits;
    let maxExUnits = ExUnits.new(toBigNum(memory), toBigNum(steps));
    let plutusScripts: { purpose: RedeemerTag, script: PlutusScript, index: number, scriptRef?: { hash: string, index: number }, data?: any, exUnits: ExUnits }[] =
        [{
            purpose: RedeemerTag.new_mint(),
            script: plutusScript,
            index: 0,
            exUnits: maxExUnits,
            // scriptRef: {
            //     hash: "85443d4120b37394af1516fcfea545472c1db960d5ad95adadbdb28105b9baa4",
            //     index: 0
            // }, 
            /*data: "MintNFT",*/
        }];

    const assets: TokenWallet[] = [];
    let mint_cost = 0;
    for (const t of tokens) {
        const token = new TokenWallet(
            new AssetWallet(policyId, (t.cip68_version ? CIP68_RNFT_PREFIX : '') + Buffer.from(t.asset_name, 'utf-8').toString('hex'), 1),
            plutusScript,
            undefined,
            script.reference_address,
            t.metadata
        )
        assets.push(token);
        const min_ada = Seed.getMinUtxoValueWithAssets(t.receiverAddress, [token.asset], null, null, configNetwork, 'hex');
        mint_cost += min_ada;
        outputs.push({
            "amount": {
                "quantity": min_ada,
                "unit": WalletswalletIdpaymentfeesAmountUnitEnum.Lovelace
            },
            "address": t.receiverAddress,
            "assets": [{
                policy_id: policyId,
                asset_name: token.asset.asset_name,
                quantity: token.asset.quantity
            }]
        });
    }
    // check tokens mint 'CIP-0068'
    const referenceUtxos = Seed.getRefenceTokenUtxos(assets, configNetwork);
    for (const refUtxo of referenceUtxos) {
        mint_cost += refUtxo.amount.quantity;
        outputs.push(refUtxo);
        assets.push(...refUtxo.assets.map((t: any) => new TokenWallet(
            new AssetWallet(policyId, t.asset_name, 1),
            plutusScript
        )))
    }

    const changes = remaining - mint_cost;
    console.log('Remaining:', remaining);
    console.log('Mint COst:', mint_cost);
    
    if (changes >= Seed.getMinUtxoValue(change_address, configNetwork)) {
        change.push({
            "address": change_address,
            "amount": {
                "quantity": changes,
                "unit": WalletswalletIdpaymentfeesAmountUnitEnum.Lovelace
            },
            "assets": []
        });
    }

    let buildOpts = {
        startSlot: 0,
        config: configNetwork,
    };


    const response = await axios.get(`${blockfrostUrl}/blocks/latest`, {
        headers: {
            'project_id': blockfrostKey
        }
    });

    const ttl = response.data.slot + 86400; // 24h, needs to be less than 36 hours to avoid possible parameters changes
    let tx = Seed.buildTransactionMultisig(total, inputs, outputs, change, ttl, assets, scripts, signingKeys, requirePolicyKeys, plutusScripts, collateral, buildOpts);
    let signed = tx.build();

    // adjust redeemer exUnits
    try {
        const exUnitsResponse = await axios.post(`${blockfrostUrl}/utils/txs/evaluate`, signed, {
            headers: {
                'Content-Type': 'application/cbor',
                'Accept': 'application/json',
                'project_id': blockfrostKey
            }
        });
        console.log(JSON.stringify(exUnitsResponse.data.result, null, 2));
        if (exUnitsResponse.data.result['EvaluationFailure']) {
            return { error: exUnitsResponse.data.result['EvaluationFailure'] };
        }
        const executionUnits = exUnitsResponse.data.result.EvaluationResult['mint:0'];
        maxExUnits = ExUnits.new(toBigNum(Math.floor(executionUnits.memory * 1.1)), toBigNum(Math.floor(executionUnits.steps * 1.1)));
        plutusScripts = [{
            purpose: RedeemerTag.new_mint(),
            script: plutusScript,
            index: 0,
            exUnits: maxExUnits,
        }];
        const multisigTx = Seed.buildTransactionMultisig(total, inputs, outputs, change, ttl, assets, scripts, signingKeys, requirePolicyKeys, plutusScripts, collateral, buildOpts);
        const encryptKey = process.env.ENCRYPT_KEY!;
        const multi = encrypt(encryptKey, multisigTx.toString())
        signed = multisigTx.build();
        return { tx: signed, multi };
    } catch (e) {
        console.log('Error:', e);
        return { error: e };
    }
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



function rebuildTransaction(partialTx: Transaction, multi: MultisigTransaction, witnessSet: TransactionWitnessSet): { tx?: Transaction, isValid: boolean } {
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

function encrypt(secretKey: string, text: crypto.BinaryLike, encoding: BufferEncoding = 'hex'): string {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return encrypted.toString(encoding);
}

function decrypt(
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