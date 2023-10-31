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

import { WalletswalletIdpaymentfeesAmount } from ".";

/**
 * 
 * @export
 * @interface WalletswalletIdtransactionsInputs
 */
export interface WalletswalletIdtransactionsInputs {
    /**
     * 
     * @type {string}
     * @memberof WalletswalletIdtransactionsInputs
     */
    address?: any;
    /**
     * 
     * @type {WalletswalletIdpaymentfeesAmount}
     * @memberof WalletswalletIdtransactionsInputs
     */
    amount?: WalletswalletIdpaymentfeesAmount;
    /**
     * A flat list of assets.
     * @type {Array&lt;WalletsAssetsAvailable&gt;}
     * @memberof WalletswalletIdtransactionsInputs
     */
    assets?: any;
    /**
     * A unique identifier for this transaction
     * @type {string}
     * @memberof WalletswalletIdtransactionsInputs
     */
    id: any;
    /**
     * 
     * @type {number}
     * @memberof WalletswalletIdtransactionsInputs
     */
    index: any;
}
