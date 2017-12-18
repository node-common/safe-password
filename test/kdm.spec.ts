import {SafePasswordHelper} from "../dist";
import {expect, assert} from "chai";
import "mocha";

describe("KeyDerivationModel", () => {

    /*
     *  Test automated password generation
     */
    it("Should create and verify password abcd1234 as Hash String", () => {

        /*
         *  Generate password in automated mode
         */
        SafePasswordHelper
            .get()
            .standard()
            .encodeAuto("abcd1234")
            .then((result) => {

            expect(typeof result === "string", "Result of password encoding should be a string");

            expect(result.split("@").length === 3, "Result password should have at least 2 delimiters");

            //console.log("Password generated with automated generator is:", result);

            /*
             *  Check password generated in automated mode for validity
             */
            SafePasswordHelper
                .get()
                .standard()
                .checkAuto("abcd1234", result)
                .then(result => {

                    expect(typeof result === "boolean", "Result should be boolean");

                    expect(result === true, "Password should match on verification");

                    //console.log("Successfully matched");

            }, err => assert.fail(err.message));

        }, err => assert.fail(err.message));

    });

});