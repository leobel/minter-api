import { CreateScriptDto } from "../models/create-script.dto";
import { applyParamsToScript, Data, Lucid, MintingPolicy, SpendingValidator } from "lucid-cardano";
import { Seed } from "../utils";
import source_scripts from "../scripts/source_scripts.json";
import { buildMintPolicy, buildValidator, label444, timeToSlot, TOKEN_LABES } from "../cli/utils";

export async function createScript(data: CreateScriptDto){
    const { label, type, network, signers, before, after } = data;
    const lucidNetwork: any = network[0].toUpperCase() + network.slice(1);
    const lucid = await Lucid.new(undefined, lucidNetwork);

    const policyType = type || 'All';
    const sPolicy: any = {
        type: policyType,
        scripts: [
        ],
        keyHash: null,
        slot: null,
        require: null,
    };
    const pkhs = [];
    for (const addr of signers) {
        const pkh = Seed.getAddressKeyHash(addr)!;
        console.log('Pub Key:', pkh);
        sPolicy.scripts.push({
            type: 'Sig',
            keyHash: pkh,
            slot: null,
            require: null
        });
        pkhs.push(pkh);
    }

    if (before) {
        sPolicy.scripts.push({
            type: 'Before',
            keyHash: null,
            slot: BigInt(timeToSlot(before, network)),
            require: null
        })
    }
    if (after) {
        sPolicy.scripts.push({
            type: 'After',
            keyHash: null,
            slot: BigInt(timeToSlot(after, network)),
            require: null
        })
    }

    const userTokenLabel = TOKEN_LABES[label] || label444;
    const validator: SpendingValidator = buildValidator(userTokenLabel, sPolicy);
    const referenceAddress = lucid.utils.validatorToAddress(validator);
    const validatorScriptHash = lucid.utils.validatorToScriptHash(validator);
    console.log('Validator hash', validatorScriptHash);
    console.log('Valiadator address', referenceAddress);

    console.log("\n----------------------------------------------------------------------------\n");

    const mintPolicy: MintingPolicy = buildMintPolicy(userTokenLabel, validatorScriptHash, sPolicy);
    const policyId = lucid.utils.mintingPolicyToId(mintPolicy);
    console.log('Policy Id', policyId);
    console.log('Mint Script size (source):', Buffer.from(source_scripts.policy, 'hex').byteLength);
    console.log('Refe Script size (source):', Buffer.from(source_scripts.reference, 'hex').byteLength);
    console.log('Mint Script size:', Buffer.from(mintPolicy.script, 'hex').byteLength);
    console.log('Refe Script size:', Buffer.from(validator.script, 'hex').byteLength);

    return {
        policy_id: policyId, 
        signers: pkhs, 
        reference_address: referenceAddress, 
        mint: mintPolicy.script,
        reference: validator.script,
        policy: JSON.parse(JSON.stringify(sPolicy, (key, value) => key == 'slot' && value ? value.toString() : value, 2))
    }
}