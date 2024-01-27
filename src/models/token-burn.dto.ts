export interface BurnTokenData {
    script: {
        policy_id: string;
        signers: string[];
        reference_address: string;
        mint: string;
        reference: string;
    },
    tokens: { asset_name: string }[];
    payments: string[];
    collaterals: string[];
    change_address: string;
}