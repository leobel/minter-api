export interface MintTokenData {
    script: {
        policy_id: string;
        signers: string[];
        reference_address: string;
        mint: string;
    },
    tokens: {[key: string]: {
        asset_name: string;
        // cip68_version: 1,
        metadata: any;
        // referenceAddress: cip68.reference_address
    }[]};
    payments: string[];
    collaterals: string[];
    change_address: string;
}