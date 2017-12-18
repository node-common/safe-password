import {SafePasswordDigestTypes} from "../index";

export class SafePasswordConfigure {

    private _hashIterations: number = 100000;

    private _preferredPasswordLength: number = 256;

    private _preferredKeyLength: number = 64;

    private _preferredDigestMethod: SafePasswordDigestTypes = SafePasswordDigestTypes.SHA256;

    private _defaultPasswordEncryptionDelimiter: string = "@";

    constructor() {

    }

    /**
     * ------------------------------------------------------------------------------
     * @param {number} num
     * @returns {SafePasswordConfigure}
     */
    public setHashIterations(num: number) : SafePasswordConfigure {

        this._hashIterations = Number(num) > 0 ? Number(num) : 100000;

        return this;

    }

    /**
     *
     * ------------------------------------------------------------------------------
     * @param {number} num
     * @returns {SafePasswordConfigure}
     */
    public setPreferredKeyLength(num: number) : SafePasswordConfigure {

        this._preferredKeyLength = Number(num) > 0 ? Number(num) : 64;

        return this;

    }

    /**
     *
     * ------------------------------------------------------------------------------
     * @param {number} num
     * @returns {SafePasswordConfigure}
     */
    public setPreferredPasswordLength(num: number) : SafePasswordConfigure {

        this._preferredPasswordLength = Number(num) > 0 ? Number(num) : 256;

        return this;

    }

    /**
     *
     * ------------------------------------------------------------------------------
     * @param {SafePasswordDigestTypes} method
     * @returns {SafePasswordConfigure}
     */
    public setPreferredDigestMethod(method: SafePasswordDigestTypes) : SafePasswordConfigure {

        for (let item in SafePasswordDigestTypes) {

            if (item === method)

                this._preferredDigestMethod = method;

        }

        return this;

    }

    /**
     *
     * ------------------------------------------------------------------------------
     * @param {string} delimiter
     * @returns {SafePasswordConfigure}
     */
    public setDefaultPasswordEncryptionDelimiter(delimiter: string) : SafePasswordConfigure {

        this._defaultPasswordEncryptionDelimiter = delimiter;

        return this;

    }

    /**
     * ------------------------------------------------------------------------------
     * @returns {number}
     */
    public hashIterations(): number {

        return this._hashIterations;

    }

    /**
     * ------------------------------------------------------------------------------
     * @returns {number}
     */
    public preferredKeyLength(): number {

        return this._preferredKeyLength;

    }

    /**
     * ------------------------------------------------------------------------------
     * @returns {number}
     */
    public preferredPasswordLength(): number {

        return this._preferredPasswordLength;

    }

    /**
     *
     * ------------------------------------------------------------------------------
     * @returns {SafePasswordDigestTypes}
     */
    public preferredDigestMethod(): SafePasswordDigestTypes {

        return this._preferredDigestMethod;

    }

    /**
     *
     * ------------------------------------------------------------------------------
     * @returns {string}
     */
    public defaultPasswordEncryptionDelimiter(): string {

        return this._defaultPasswordEncryptionDelimiter;

    }

}