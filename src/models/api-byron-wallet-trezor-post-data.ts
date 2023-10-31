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
 * 
 * @export
 * @interface ApiByronWalletTrezorPostData
 */
export interface ApiByronWalletTrezorPostData {
    /**
     * 
     * @type {string}
     * @memberof ApiByronWalletTrezorPostData
     */
    style?: ApiByronWalletTrezorPostDataStyleEnum;
    /**
     * 
     * @type {string}
     * @memberof ApiByronWalletTrezorPostData
     */
    name: any;
    /**
     * A master passphrase to lock and protect the wallet for sensitive operation (e.g. sending funds)
     * @type {string}
     * @memberof ApiByronWalletTrezorPostData
     */
    passphrase: any;
    /**
     * A list of mnemonic words
     * @type {Array&lt;string&gt;}
     * @memberof ApiByronWalletTrezorPostData
     */
    mnemonic_sentence: any;
}

/**
    * @export
    * @enum {string}
    */
export enum ApiByronWalletTrezorPostDataStyleEnum {
    Trezor = 'trezor'
}

