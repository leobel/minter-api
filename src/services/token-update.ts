import { Ed25519KeyHash, ExUnits, NativeScript, PlutusScript, PrivateKey, RedeemerTag, TransactionUnspentOutput } from "@emurgo/cardano-serialization-lib-nodejs";
import { UpdateTokenData } from "../models/token-update.dto";
import { ApiCoinSelectionChange, ApiCoinSelectionInputs, WalletswalletIdpaymentfeesAmountUnitEnum, WalletswalletIdpaymentfeesPayments } from "../models";
import { Mainnet, Testnet } from "../config/network.config";
import { calculateInputs, encrypt, getExUnits, getLatestBlock, getMaxExUnits, getRefenceTokenInfo, sortInputs } from "./crypto";
import { CIP68_REFERENCE_PREFIX, Seed } from "../utils";
import { TokenWallet } from "../wallet/token-wallet";
import { AssetWallet } from "../wallet/asset-wallet";

export async function updateToken(data: UpdateTokenData) {
    const { script, tokens: tTokens, payments, collaterals, change_address } = data;
    const network = script.reference_address.startsWith('addr_test') ? 'preprod' : 'mainnet';

    const { network: configNetwork, blockfrostKey, blockfrostUrl } = network == 'mainnet' ? {
        network: Mainnet,
        blockfrostKey: process.env.BLOCKFROST_KEY_MAINNET!,
        blockfrostUrl: process.env.BLOCKFROST_URL_MAINNET!
    } : { 
        network: Testnet,
        blockfrostKey: process.env.BLOCKFROST_KEY_TESTNET!,
        blockfrostUrl: process.env.BLOCKFROST_URL_TESTNET!

    };

    // get inputs
    let inputs = payments.map(d => TransactionUnspentOutput.from_bytes(Buffer.from(d, 'hex')));

    // get outputs
    const outputs: WalletswalletIdpaymentfeesPayments[] = [];

    // get change
    const change: ApiCoinSelectionChange[] = [];

    // get collaterals
    const collateral = collaterals.map(c => TransactionUnspentOutput.from_bytes(Buffer.from(c, 'hex')));

    const signingKeys: PrivateKey[] = [];

    const requirePolicyKeys = script.signers.map(s => Ed25519KeyHash.from_hex(s));

    const scripts: NativeScript[] = [];

    // get total input, remaining and outputs
    // buyer assets that where sent to us
    let { total, remaining, outputs: tokenOutputs } = calculateInputs(inputs, configNetwork);

    outputs.push(...tokenOutputs);

    // plutus script section 
    const refScript = PlutusScript.from_bytes_v2(Buffer.from(script.reference, 'hex'));
    let maxExUnits = getMaxExUnits(configNetwork);

    // add ref token inputs & plutusScripts
    const policyId = script.policy_id;
    const tokens = [];
    let plutusScripts: { purpose: RedeemerTag, script: PlutusScript, index: number, data?: any, exUnits: ExUnits, inputData?: any, ctrIndex?: number }[] = [];
    const referenceTokensInputs: { hash: string, index: number, datum: string }[] = [];
    try {
        for (const { asset_name, metadata } of tTokens) {
            const cip68ref_name = CIP68_REFERENCE_PREFIX + Buffer.from(asset_name, 'utf-8').toString('hex');
            const unit = policyId + cip68ref_name;
            const { tx_hash, index, amount, datum } = await getRefenceTokenInfo(blockfrostUrl, blockfrostKey, unit);
            referenceTokensInputs.push({ hash: tx_hash, index, datum });
            const quantity = Number(amount.quantity);
            total += quantity;
            remaining += quantity;
            const input: ApiCoinSelectionInputs = { // ref Token
                "id": tx_hash,
                "index": index,
                "amount": amount,
                "address": script.reference_address,
                "assets": [
                    {
                        "policy_id": policyId,
                        "asset_name": cip68ref_name,
                        "quantity": 1
                    }
                ],
            };

            inputs.push(...Seed.coinSelectionInputToUtxos([input]));

            tokens.push({
                asset_name,
                cip68ref_name,
                cip68_version: 1,
                metadata,
                referenceAddress: script.reference_address,
                datum,
            });
        }

        // add script based on reference tokens final position on inputs
        inputs = sortInputs(inputs);
        for (let { hash, index, datum } of referenceTokensInputs) {
            const i = inputs.findIndex(t => {
                const input = t.input();
                return input.transaction_id().to_hex() == hash && input.index() == index;
            });

            plutusScripts.push({
                purpose: RedeemerTag.new_spend(),
                script: refScript,
                index: i, // e.g. 0
                exUnits: maxExUnits,
                ctrIndex: 2, // ctr index 2 => Upgrade && ref Token at input index 0 (ordered alphanumeric by hash then index)
                inputData: datum // old metadata datum
            }); // ref script);
        }

        const assets: TokenWallet[] = tokens.flatMap(t => [
            new TokenWallet( // ref Token
                new AssetWallet(policyId, t.cip68ref_name, 1),
                refScript,
                undefined,
                t.referenceAddress,
                t.metadata
            ),
        ]);

        const referenceUtxos = Seed.getRefenceTokenUtxos(assets, configNetwork);
        let refTokensCost = 0;
        for (const refUtxo of referenceUtxos) {
            refTokensCost += refUtxo.amount.quantity;
            outputs.push(refUtxo);
        }

        const changes = remaining - refTokensCost;
        console.log('Total:', total);
        console.log('Remaining:', remaining);
        console.log('Change:', changes);
        console.log('Ref Token Cost:', refTokensCost);

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

        const slot = await getLatestBlock(blockfrostUrl, blockfrostKey);

        const ttl = slot + 86400; // 24h, needs to be less than 36 hours to avoid possible parameters changes
        let tx = Seed.buildTransactionMultisig(total, inputs, outputs, change, ttl, [], scripts, signingKeys, requirePolicyKeys, plutusScripts, collateral, buildOpts);
        let signed = tx.build();
        
        // adjust redeemer exUnits
        maxExUnits = await getExUnits(blockfrostUrl, blockfrostKey, signed, 'spend');
        plutusScripts = plutusScripts.map(ps => {
            ps.exUnits = maxExUnits;
            return ps;
        });
        const multisigTx = Seed.buildTransactionMultisig(total, inputs, outputs, change, ttl, [], scripts, signingKeys, requirePolicyKeys, plutusScripts, collateral, buildOpts);
        const encryptKey = process.env.ENCRYPT_KEY!;
        const multi = encrypt(encryptKey, multisigTx.toString())
        signed = multisigTx.build();
        return { tx: signed, multi };
    } catch (e) {
        console.log('Error:', e);
        return { error: e };
    }
}