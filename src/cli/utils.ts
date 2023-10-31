import { applyParamsToScript, Data, Lucid, MintingPolicy, SpendingValidator } from "lucid-cardano";
import source_scripts from "../scripts/source_scripts.json";

export const label100 = "000643b0";
export const label222 = "000de140";
export const label444 = "001bc280";
export const label333 = "0014df10";
export const TOKEN_LABES: { [key: string | number]: string } = {
    ['100']: label100,
    ['222']: label222,
    ['444']: label444,
    ['333']: label333,
}

const ScriptType = Data.Enum([
    Data.Literal("Sig"),
    Data.Literal("All"),
    Data.Literal("Any"),
    Data.Literal("AtLeast"),
    Data.Literal("After"),
    Data.Literal("Before"),
]);
type ScriptType = Data.Static<typeof ScriptType>;

const NativeScript = Data.Object({
    type: ScriptType,
    keyHash: Data.Nullable(Data.Bytes({ minLength: 28, maxLength: 28 })),
    slot: Data.Nullable(Data.Integer()),
    require: Data.Nullable(Data.Integer())
});
type NativeScript = Data.Static<typeof NativeScript>;

const Policy = Data.Object({
    type: ScriptType,
    keyHash: Data.Nullable(Data.Bytes({ minLength: 28, maxLength: 28 })),
    slot: Data.Nullable(Data.Integer()),
    require: Data.Nullable(Data.Integer()),
    scripts: Data.Nullable(Data.Array(NativeScript))
});

const ReferenceSchema = Data.Tuple([
    Data.Bytes({ minLength: 4, maxLength: 4 }), // label222 or label444
    Data.Bytes({ minLength: 4, maxLength: 4 }), // label100
    Policy
]);

const ConstractDetails = Data.Object({
    refAddress: Data.Bytes({ minLength: 28, maxLength: 28 }), // reference script hash
    royaltyName: Data.Bytes({ minLength: 0, maxLength: 32 }) // royalty token name (could be empty string)
});

const MintSchema = Data.Tuple([
    Data.Bytes({ minLength: 4, maxLength: 4 }), // label222 or label444
    Data.Bytes({ minLength: 4, maxLength: 4 }), // label100
    Policy,
    ConstractDetails
])
type MintSchema = Data.Static<typeof MintSchema>;
type ReferenceSchema = Data.Static<typeof ReferenceSchema>;

const MintAction = Data.Enum([
    Data.Literal("MintNFT"),
    Data.Literal("BurnNFT"),
    Data.Literal("MintExtra"),
]);
type MintAction = Data.Static<typeof MintAction>;

const Metadata = Data.Map(Data.Bytes(), Data.Any());
type Metadata = Data.Static<typeof Metadata>;

const DatumMetadata = Data.Object({
    metadata: Metadata,
    version: Data.Integer({ minimum: 1, maximum: 1 }),
    extra: Data.Any(),
});
type DatumMetadata = Data.Static<typeof DatumMetadata>;

export function buildValidator(tokenLabel: string, sPolicy: any) {
    const validator: SpendingValidator = {
        type: "PlutusV2",
        script: applyParamsToScript(
            source_scripts.reference,
            [
                tokenLabel, // label222 or label444
                label100,
                sPolicy
            ],
            ReferenceSchema
        ),
    };
    return validator
}

export function buildMintPolicy(tokenLabel: string, refAddress: string, sPolicy: any, royaltyName = '') {
    const validator: MintingPolicy = {
        type: "PlutusV2",
        script: applyParamsToScript(
            source_scripts.policy,
            [
                tokenLabel, // label222 or label444
                label100,
                sPolicy,
                {
                    refAddress,
                    royaltyName
                }
            ],
            MintSchema
        ),
    };
    return validator;
}

export const SHELLEY_ERA_POSIX_TIME = 1596491091;
export const SHELLEY_ERA_SLOT = 4924800;
export const SHELLEY_ERA_POSIX_TIME_TESTNET = 1655769600;
export const SHELLEY_ERA_SLOT_TESTNET = 86400;

export function slotToTime(slot: number, network = 'mainnet'): Date {
    const startTime = network == 'testnet' ? SHELLEY_ERA_POSIX_TIME_TESTNET : SHELLEY_ERA_POSIX_TIME;
    const startSlot = network == 'testnet' ? SHELLEY_ERA_SLOT_TESTNET : SHELLEY_ERA_SLOT;
    return new Date((startTime + (slot - startSlot)) * 1000)
}

export function timeToSlot(time: number | string, network = 'mainnet'): number {
    const startSlot = network == 'testnet' ? SHELLEY_ERA_SLOT_TESTNET : SHELLEY_ERA_SLOT;
    const startSlotTime = slotToTime(startSlot, network);
    const ellapsedSlots = Math.floor((new Date(time).getTime() - startSlotTime.getTime()) / 1000);
    return startSlot + ellapsedSlots;
}