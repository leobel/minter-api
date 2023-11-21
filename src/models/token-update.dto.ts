export interface UpdateTokenData {
    script: {
        policy_id: string;
        signers: string[];
        reference_address: string;
        reference: string;
    },
    tokens: { asset_name: string, metadata: any }[];
    payments: string[];
    collaterals: string[];
    change_address: string;
}