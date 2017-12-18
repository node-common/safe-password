import {KeyDerivationModel} from "./models/key.derivation.model";
import {SafePasswordConfigure} from "./conf/safe.password.configure";

/**
 *  Safe password
 *  ------------------------------------------------------------------------------
 *  Set of methods to generate some password in a hassle-free way
 */
export class SafePassword {

    private conf: SafePasswordConfigure = null;

    private kdModel: KeyDerivationModel = null;

    constructor() {

        this.conf = new SafePasswordConfigure();

    }

    /**
     * Start configuration of Safe Password
     * ------------------------------------------------------------------------------
     * @returns {SafePasswordConfigure}
     */
    public configure() : SafePasswordConfigure {

        return this.conf;

    }

    /**
     * Standard password generation
     * ------------------------------------------------------------------------------
     * Standard encrypted password generation
     * currently https://tools.ietf.org/html/rfc8018 (PBKDF2)
     *
     * @returns {KeyDerivationModel}
     */
    public standard() {

        if(this.kdModel === null)

            this.kdModel = new KeyDerivationModel(this.conf);

        return this.kdModel;

    }

}

/**
 *  Safe password helper is a static container for Safe password class
 *  ------------------------------------------------------------------------------
 */
export class SafePasswordHelper {

    private static instance: SafePassword = null;

    /**
     * Returns current instance of SafePassword attached to container
     * ------------------------------------------------------------------------------
     * @returns {SafePassword}
     */
    public static get() {

        if(this.instance === null)

            this.init();

        return this.instance;

    }

    /**
     * Will reset and re-instantiate Safe Password for this container
     * ------------------------------------------------------------------------------
     */
    public static init() {

        this.instance = new SafePassword();

    }

}

/**
 *  ------------------------------------------------------------------------------
 */
export enum SafePasswordDigestTypes {
    "SHA1" = "sha1",
    "SHA256" = "sha256",
    "SHA384" = "sha384",
    "SHA512" = "sha512"
}

/**
 *  ------------------------------------------------------------------------------
 */
export enum SafePasswordStringEncodingTypes {
    "HEX" = "hex"
}