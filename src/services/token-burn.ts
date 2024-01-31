import axios from 'axios';
import { Ed25519KeyHash, ExUnits, NativeScript, PlutusScript, PrivateKey, RedeemerTag, Transaction, TransactionUnspentOutput, TransactionWitnessSet, Vkeywitnesses } from "@emurgo/cardano-serialization-lib-nodejs";
import { BurnTokenData } from "../models/token-burn.dto";
import { CIP68_REFERENCE_PREFIX, CIP68_RNFT_PREFIX, Seed, toBigNum } from "../utils";
import { Mainnet, Testnet } from "../config/network.config";
import { TokenWallet } from "../wallet/token-wallet";
import { AssetWallet } from "../wallet/asset-wallet";
import { ApiCoinSelectionChange, ApiCoinSelectionInputs, WalletswalletIdpaymentfeesAmountUnitEnum, WalletswalletIdpaymentfeesPayments } from "../models";
import { SignTxData } from '../models/sign-tx.dto';
import { MultisigTransaction } from '../models/multisig-transaction';
import { calculateInputs, decrypt, encrypt, getExUnits, getLatestBlock, getMaxExUnits, getRefenceTokenInfo, parseInputs, sortInputs } from './crypto';


export async function burnToken(data: BurnTokenData) {
    const { script, tokens: tTokens, payments, collaterals, change_address } = data;
    const network = script.reference_address.startsWith('addr_test') ? 'preprod' : 'mainnet';

    const policyId = script.policy_id;
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
    let inputsMap = parseInputs(payments);

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
    let { total, remaining, outputs: tokenOutputs } = calculateInputs(Array.from(inputsMap.values()), configNetwork);
    console.log('Initital total:', total);
    console.log('Initial remaining:', remaining);
    
    outputs.push(...tokenOutputs);

    // plutus script section 
    const mintScript = PlutusScript.from_bytes_v2(Buffer.from(script.mint, 'hex'));
    const refScript = PlutusScript.from_bytes_v2(Buffer.from(script.reference, 'hex'));
    let maxExUnits = getMaxExUnits(configNetwork);
    let plutusScripts: { purpose: RedeemerTag, script: PlutusScript, index: number, scriptRef?: { hash: string, index: number }, data?: any, exUnits: ExUnits, inputData?: any, ctrIndex?: number }[] =
        [{
            purpose: RedeemerTag.new_mint(),
            script: mintScript,
            index: 0,
            exUnits: maxExUnits,
            ctrIndex: 1 // burn script
            // scriptRef: {
            //     hash: "85443d4120b37394af1516fcfea545472c1db960d5ad95adadbdb28105b9baa4",
            //     index: 0
            // }, 
            /*data: "MintNFT",*/
        }];
    const referenceTokensInputs: { hash: string, index: number, datum: string }[] = [];
    const assets: TokenWallet[] = [];
    for (const t of tTokens) {
        const cip68ref_name = CIP68_REFERENCE_PREFIX + Buffer.from(t.asset_name, 'utf-8').toString('hex');
        const cip68user_name = CIP68_RNFT_PREFIX + Buffer.from(t.asset_name, 'utf-8').toString('hex');
        let unit = policyId + cip68ref_name;
        const { tx_hash, index, amount, datum } = await getRefenceTokenInfo(blockfrostUrl, blockfrostKey, unit);
        referenceTokensInputs.push({ hash: tx_hash, index, datum });
        let key = `${tx_hash}#${index}`;
        total += Number(amount.quantity);
        remaining += Number(amount.quantity);
        const refTokenInput: ApiCoinSelectionInputs = { // ref Token
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
        inputsMap.set(key, Seed.coinSelectionInputToUtxos([refTokenInput])[0]);
        unit = policyId + cip68user_name;
        const { address, tx_hash: uTx_hash, index: uIndex, amount: uAmount } = await getRefenceTokenInfo(blockfrostUrl, blockfrostKey, unit, false);
        key = `${uTx_hash}#${uIndex}`;
        if (!inputsMap.has(key)) { // could be already in the inputs coming from wallet payments
            remaining += Number(uAmount.quantity);
            total += Number(uAmount.quantity);
            const userTokenInput: ApiCoinSelectionInputs = { // user Token
                "id": uTx_hash,
                "index": uIndex,
                "amount": uAmount,
                "address": address,
                "assets": [
                    {
                        "policy_id": policyId,
                        "asset_name": cip68user_name,
                        "quantity": 1
                    }
                ],
            };
            inputsMap.set(key, Seed.coinSelectionInputToUtxos([userTokenInput])[0]);
        } else { // if already in the inputs, we need to remove it from the outputs
            const i = outputs.findIndex(out => out.assets?.some(asset => asset.policy_id + asset.asset_name == unit));
            remaining += outputs[i].amount.quantity;
            outputs.splice(i, 1);
        }

        assets.push(new TokenWallet(
            new AssetWallet(policyId, cip68user_name, -1),
            mintScript,
            undefined,
            script.reference_address
        ));
        assets.push(new TokenWallet(
            new AssetWallet(policyId, cip68ref_name, -1),
            refScript,
            undefined,
        ));
    }

    // add script based on reference tokens final position on inputs
    const inputs = sortInputs(Array.from(inputsMap.values()));
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
            ctrIndex: 0, // ctr index 0 => Burn && ref Token at input index 0 (ordered alphanumeric by hash then index)
            inputData: datum // old metadata datum
        }); // ref script);
    }

    // add total as change. Tx fee will be deducted from here
    console.log('Total:', total);
    console.log('Remaining:', remaining);
    change.push({
        "address": change_address,
        "amount": {
            "quantity": remaining,
            "unit": WalletswalletIdpaymentfeesAmountUnitEnum.Lovelace
        },
        "assets": []
    });


    let buildOpts = {
        startSlot: 0,
        config: configNetwork,
    };

    const slot = await getLatestBlock(blockfrostUrl, blockfrostKey);

    const ttl = slot + 86400; // 24h, needs to be less than 36 hours to avoid possible parameters changes
    let tx = Seed.buildTransactionMultisig(total, inputs, outputs, change, ttl, assets, scripts, signingKeys, requirePolicyKeys, plutusScripts, collateral, buildOpts);
    let signed = tx.build();
    
    try {
        // adjust redeemer exUnits
        const maxMintExUnits = await getExUnits(blockfrostUrl, blockfrostKey, signed);
        const maxSpendExUnits = await getExUnits(blockfrostUrl, blockfrostKey, signed, 'spend');
        plutusScripts[0].exUnits = maxMintExUnits; // mint script
        for (let i = 1; i < plutusScripts.length; i++) { // spend scripts
            plutusScripts[i].exUnits = maxSpendExUnits;
        }
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
