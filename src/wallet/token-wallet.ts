import { NativeScript, PlutusScript } from "@emurgo/cardano-serialization-lib-nodejs";
import { Bip32KeyPair } from "../utils";
import { AssetWallet } from "./asset-wallet";

export class TokenWallet {
	asset: AssetWallet;
	script?: NativeScript | PlutusScript;
	scriptKeyPairs?: Bip32KeyPair[];
	referenceAddress?: string;
	metadata?: any;

	constructor(asset: AssetWallet, script?: NativeScript | PlutusScript, scriptKeyPairs?: Bip32KeyPair[], referenceAddress?: string, metadata?: any) {
		this.asset = asset;
		this.script = script;
		this.scriptKeyPairs = scriptKeyPairs;
		this.referenceAddress = referenceAddress;
		this.metadata = metadata;
	}
}
