export interface CreateScriptDto {
    label: string;
    network: string;
    type?: string;
    signers: string[];
    before?: string;
    after?: string;
}