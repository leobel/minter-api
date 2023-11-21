import axios from 'axios';
import { Ed25519KeyHash, ExUnits, NativeScript, PlutusScript, PrivateKey, RedeemerTag, Transaction, TransactionUnspentOutput, TransactionWitnessSet, Vkeywitnesses } from "@emurgo/cardano-serialization-lib-nodejs";
import { MintTokenData } from "../models/token-mint.dto";
import { CIP68_RNFT_PREFIX, Seed, toBigNum } from "../utils";
import { Mainnet, Testnet } from "../config/network.config";
import { TokenWallet } from "../wallet/token-wallet";
import { AssetWallet } from "../wallet/asset-wallet";
import { ApiCoinSelectionChange, WalletswalletIdpaymentfeesAmountUnitEnum, WalletswalletIdpaymentfeesPayments } from "../models";
import { SignTxData } from '../models/sign-tx.dto';
import { MultisigTransaction } from '../models/multisig-transaction';
import { calculateInputs, decrypt, encrypt, getExUnits, getLatestBlock, getMaxExUnits } from './crypto';


export async function mintToken(data: MintTokenData) {
    const { script, tokens: tTokens, payments, collaterals, change_address } = data;
    const network = script.reference_address.startsWith('addr_test') ? 'preprod' : 'mainnet';

    const policyId = script.policy_id;
    const tokens = Object.entries(tTokens).flatMap(([address, tokens]) => tokens.map(data => ({
        ...data,
        cip68_version: 1,
        receiverAddress: address,
    })));
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

    // get total input, remaining and outputs
    // buyer assets that where sent to us
    let { total, remaining, outputs: tokenOutputs } = calculateInputs(inputs, configNetwork);

    outputs.push(...tokenOutputs);

    // plutus script section 
    const plutusScript = PlutusScript.from_bytes_v2(Buffer.from(script.mint, 'hex'));
    let maxExUnits = getMaxExUnits(configNetwork);
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

    const slot = await getLatestBlock(blockfrostUrl, blockfrostKey);

    const ttl = slot + 86400; // 24h, needs to be less than 36 hours to avoid possible parameters changes
    let tx = Seed.buildTransactionMultisig(total, inputs, outputs, change, ttl, assets, scripts, signingKeys, requirePolicyKeys, plutusScripts, collateral, buildOpts);
    let signed = tx.build();

    // adjust redeemer exUnits
    try {
        maxExUnits = await getExUnits(blockfrostUrl, blockfrostKey, signed);
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
