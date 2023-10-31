/* tslint:disable */
/* eslint-disable */
/**
 * Cardano Wallet Backend API
 * <p align=\"right\"><img style=\"position: relative; top: -10em; margin-bottom: -12em;\" width=\"20%\" src=\"https://cardanodocs.com/img/cardano.png\"></img></p> 
 *
 * OpenAPI spec version: 2021.3.4
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */
/**
 * In the Mary era of Cardano, UTxO may contain native assets. These assets are represented on-chain by opaque identifiers which are meaningless to end-users. Therefore, user-facing metadata regarding each token must be stored off-chain, in a metadata registry.  Token creators may publish metadata into the registry and client applications can consume these metadata for display to end users. This will work in a similar way to how it is done for stake pool metadata. 
 * @export
 * @interface NativeAssetsMetadata
 */
export interface NativeAssetsMetadata {
    /**
     * A human-readable name for the asset, intended for display in user interfaces. 
     * @type {string}
     * @memberof NativeAssetsMetadata
     */
    name: any;
    /**
     * A human-readable description for the asset. Good for display in user interfaces. 
     * @type {string}
     * @memberof NativeAssetsMetadata
     */
    description: any;
    /**
     * An optional human-readable very short name or acronym for the asset, intended for display in user interfaces. If `ticker` is not present, then `name` will be used, but it might be truncated to fit within the available space. 
     * @type {string}
     * @memberof NativeAssetsMetadata
     */
    ticker?: any;
    /**
     * 
     * @type {NativeAssetsMetadataUnit}
     * @memberof NativeAssetsMetadata
     */
    unit?: any;
    /**
     * A URL to the policy's owner(s) or the entity website in charge of the asset. 
     * @type {string}
     * @memberof NativeAssetsMetadata
     */
    url?: any;
    /**
     * A base64-encoded `image/png` for displaying the asset. The end image can be expected to be smaller than 64KB. 
     * @type {string}
     * @memberof NativeAssetsMetadata
     */
    logo?: any;
}