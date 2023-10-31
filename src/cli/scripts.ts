import * as fs from 'fs'
import { Lucid, MintingPolicy, SpendingValidator } from "lucid-cardano";
import { Seed } from "../utils";
import { buildMintPolicy, buildValidator, label444, timeToSlot, TOKEN_LABES } from './utils';
import source_scripts from "../scripts/source_scripts.json";



const args = process.argv.slice(2).reduce((dict: { [key: string | number]: any }, cur, i, arr) => {
    if (i % 2 == 0) {
        if (dict[cur]) {
            if (Array.isArray(dict[cur])) {
                dict[cur].push(arr[i + 1]);
            } else {
                dict[cur] = [dict[cur], arr[i + 1]];
            }
        } else {
            dict[cur] = arr[i + 1];
        }
    }
    return dict;
}, {});
console.log('Args:', args);

const userTokenLabel = TOKEN_LABES[args['--label']] || label444;
const policyType = args['--type'] || 'All';
const signer = Array.isArray(args['--signer']) ? args['--signer'] : [args['--signer']];
const before = args['--before'];
const after = args['--after'];
const network = args['--network'] || 'mainnet';

const sPolicy: any = {
    type: policyType,
    scripts: [
        // {
        //     type: 'Sig',
        //     keyHash: '7033ae4fee98c32a9053d7e16aa711fcdf8155d42e59cbe99eaf23b5', // to replace
        //     slot: null,
        //     require: null
        // },
        // {
        //     type: 'Before',
        //     keyHash: null,
        //     slot: 1800764338000n,
        //     require: null
        // }
    ],
    keyHash: null,
    slot: null,
    require: null,
};

(async () => {
    // arrange
    const lucidNetwork = network[0].toUpperCase() + network.slice(1);
    const lucid = await Lucid.new(
        undefined, // new Blockfrost("https://cardano-preview.blockfrost.io/api/v0", "previewtig36zvJlerO2wL2A2ZDo7VD0MuBIjE6"),
        lucidNetwork
    );

    // const pkh = Seed.getAddressKeyHash("addr_test1qq2lamgej4xd6ycmhz3wmhpdu2me4f3x8klrmzcphcur7fm9388qnq9fyxt0c3qk0elu753ud03u598cnmsmdgh027nsjkxf5a")!;
    const pkhs = [];
    for (const addr of signer) {
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
            slot: BigInt(timeToSlot(before)),
            require: null
        })
    }
    if (after) {
        sPolicy.scripts.push({
            type: 'After',
            keyHash: null,
            slot: BigInt(timeToSlot(after)),
            require: null
        })
    }

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

    const filepath = args['--script-file'] || 'cip68.json';
    fs.writeFileSync(filepath, JSON.stringify({
        policy_id: policyId, 
        signers: pkhs, 
        reference_address: referenceAddress, 
        mint: mintPolicy.script,
        reference: validator.script,
        policy: JSON.parse(JSON.stringify(sPolicy, (key, value) => key == 'slot' && value ? value.toString() : value, 2))
    }))
})()