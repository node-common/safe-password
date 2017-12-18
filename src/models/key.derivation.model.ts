import * as Crypto from "crypto";
import {SafePasswordConfigure} from "../conf/safe.password.configure";
import {SafePasswordDigestTypes, SafePasswordStringEncodingTypes} from "../index";
import {Exception} from "ts-exceptions";

/**
 * Password model
 * ----------------------------------------------------------------------------------------------------------
 * Using Key Derivation method to produce hashed passwords salted with some random string
 *
 */
export class KeyDerivationModel {

    private delimiter: string = "@";

    private iterations: number = 100000;

    private passwordLength: number = 256;

    private keyLength: number = 64;

    private digestType: SafePasswordDigestTypes = SafePasswordDigestTypes.SHA256;

    private keyEncoding: SafePasswordStringEncodingTypes = SafePasswordStringEncodingTypes.HEX;

    constructor(conf: SafePasswordConfigure) {

        this.iterations = conf.hashIterations();
        this.keyLength = conf.preferredKeyLength();
        this.digestType = conf.preferredDigestMethod();
        this.delimiter = conf.defaultPasswordEncryptionDelimiter();
        this.passwordLength = conf.preferredPasswordLength();

    }

    /**
     * Encode some string password in automated mode
     * ----------------------------------------------------------------------------------------------------------
     * This will be producing password in automated mode and
     * password will be produced in the form of:
     *
     *  hash[delimiter]salt[delimiter]iterations
     *
     * @param {string} password
     * @returns {Promise<string>}
     */
    public async encodeAuto(password: string) : Promise<string> {

        const salt = this.getRandomString();

        return new Promise<string>((resolve, reject) => {

            Crypto.pbkdf2(password, salt, this.iterations, this.passwordLength, this.digestType, (e, key) => {

                // If error then Reject with Exception
                if(e)

                    return reject(new Exception(e.message, 400));

                // Otherwise concatenate full password using delimiter
                resolve(

                    key.toString(this.keyEncoding)
                        .concat("@" + salt + "@" + String(this.iterations))

                );

            })

        });

    }

    /**
     * Check some password against encrypted password.
     * ----------------------------------------------------------------------------------------------------------
     * Encrypted password should be product of this Model.
     *
     * Password should be representation of construction:
     *
     *  hash[delimiter]salt[delimiter]iterations
     *
     * @param {string} password
     * @param {string} encryptedPassword
     * @returns {Promise<boolean>}
     */
    public async checkAuto(password: string, encryptedPassword: string) : Promise<boolean> {

        let hash = "";
        let salt = "";
        let iterations = this.iterations;

        const decoupledPWD = encryptedPassword.split(this.delimiter);

        if(decoupledPWD.length > 0)
            hash = decoupledPWD[0];

        if(decoupledPWD.length > 1)
            salt = decoupledPWD[1];

        if(decoupledPWD.length > 2)
            iterations = Number(decoupledPWD[2]);

        return new Promise<boolean>((resolve, reject) => {

            Crypto.pbkdf2(password, salt, iterations, this.passwordLength, this.digestType, (e, key) => {

                // If error then Reject with Exception
                if(e)

                    return reject(new Exception(e.message, 400));

                // Resolve by comparing staging password hash to existing password hash
                resolve(hash === key.toString(this.keyEncoding));

            });

        });

    }

    /**
     * Encode some password.
     * ----------------------------------------------------------------------------------------------------------
     * As a result of this method - complex object will be returned.
     * Developer should store every piece of information from this
     * object in appropriate manner
     *
     * @param {string} password
     * @returns {Promise<SPKDMPassword>}
     */
    public async encode(password: string) : Promise<SPKDMPassword> {

        const salt = this.getRandomString();
        const iter = this.iterations;

        return new Promise<SPKDMPassword>((resolve, reject) => {

            Crypto.pbkdf2(password, salt, iter, this.passwordLength, this.digestType, (e, key) => {

                // If error then Reject with Exception
                if(e)

                    return reject(new Exception(e.message, 400));

                // Otherwise concatenate full password using delimiter
                resolve({
                    passwordHash: key.toString(this.digestType),
                    passwordSalt: salt,
                    hashIterations: iter
                });

            })

        });


    }

    /**
     * Check some password against set of parameters
     * ----------------------------------------------------------------------------------------------------------
     *
     * @param {string} password                     : Password provided as common string
     *
     * @param {string} encryptedPasswordHash        : Hash of password which is tested against password
     *                                                  above. Should be hash produced by this model.
     *
     * @param {string} encryptedPasswordSalt        : Salt of password which is tested against password
     *                                                  above. Should be salt which produced by this model.
     *
     * @param {number} encryptedPasswordIterations  : Iterations of hash function which was applied to the
     *                                                  previously saved password.
     * @returns {Promise<boolean>}
     */
    public async check(password: string,
                               encryptedPasswordHash: string,
                               encryptedPasswordSalt: string,
                               encryptedPasswordIterations: number) : Promise<boolean> {

        const iter = Number(encryptedPasswordIterations);

        // Check if iterations were provided as required
        if(isNaN(iter) || iter < 1)

            throw new Exception(
                "Iterations provided to Check Password should be positive Integer value", 400);

        // Return new comparison promise
        return new Promise<boolean>((resolve, reject) => {

            Crypto.pbkdf2(password, encryptedPasswordSalt, iter, this.passwordLength, this.digestType, (e, key) => {

                // If error then Reject with Exception
                if(e)

                    return reject(new Exception(e.message, 400));

                // Resolve by comparing staging password hash to existing password hash
                resolve(encryptedPasswordHash === key.toString(this.keyEncoding));

            });

        });

    }

    /**
     * Produce random string based on current configuration
     * ----------------------------------------------------------------------------------------------------------
     * @returns {string}
     */
    public getRandomString() : string {

        return Crypto.randomBytes(this.keyLength).toString(this.keyEncoding);

    }

}

/**
 * Standard password object which will be produced as a result of normal encryption
 * ----------------------------------------------------------------------------------------------------------
 */
export interface SPKDMPassword {
    passwordSalt: string,
    passwordHash: string,
    hashIterations: number
}