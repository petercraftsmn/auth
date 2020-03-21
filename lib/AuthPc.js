const JwtMiddleware = require( './JwtMiddleware' );

/**
 * This class works on req.user object
 * req object looks as follows
 * {
 *     req: {
 *         user: {
 *             id: "some id string",
 *             salt: "some salt string",
 *             hash: "password and salt hash string",
 *             token: {
 *                 header: "some token header",
 *                 payload: "some token payload"
 *             },
 *             webToken: "some web token string"
 *         }
 *     }
 * }
 *
 * req.user.token -> may contain encrypted or base 64 string or decrypted object
 * read functions -> replace encrypted token with decrypted token object and populate req.user._id
 * for this class token should be attached to req.user.token if it is coming in
 * header or body
 */
class AuthPc extends JwtMiddleware {
    constructor( keys ) {
        super( keys );
    }

    /**
     * Create random salt string for any purpose
     * @param req
     * @param res
     * @param next
     */
    async createSalt( req, res, next ) {
        req.user.salt = await this.saltCreator();
        next();
    }

    /**
     * Create hash of password + salt -> hash and attach to request
     * req.user.password and req.user.salt should be present
     * @param req
     * @param res
     * @param next
     */
    async createPasswordHash( req, res, next ) {
        req.user.hash = await this.hashCreator( req.user.password + req.user.salt );
        next();
    }

    /**
     * Create salt and password + salt -> hash and attache to req
     * req.user.password should contain password
     * @param req
     * @param res
     * @param next
     */
    async createSaltAndPasswordHash( req, res, next ) {
        req.user.salt = await this.saltCreator();
        req.user.hash = await this.hashCreator( req.user.password + req.user.salt );
        next();
    }

    /**
     * Create encrypted and signed user token and attach to req.user.token
     * req should contain
     * @param req
     * @param res
     * @param next
     */
    async createWebTokenSignedEncrypted( req, res, next ) {
        req.user.token = await this.createJWT( { type: "web" },
            {
                id: req.user.id,
                timeCreated: Date.now()
            } );
        next();
    }

    /**
     * Read encrypted and signed web token
     * @param req
     * @param res
     * @param next
     */
    async readWebTokenSignedEncrypted( req, res, next ) {
        const token = await this.readJWT( req.user.token );

        if ( token.payload.id !== 'undefined' ) {
            req.user.id = token.payload.id;
        } else {
            req.user.id = null
        }

        req.user = { ...req.user, token: token };
        next();
    }

    /**
     * Create base64 signed user token and attach to req.user.token
     * req should contain
     * @param req
     * @param res
     * @param next
     */
    async createWebTokenSignedBase64( req, res, next ) {

        // Create token string
        const tokenString = JSON.stringify( { type: "web" } ) + '.' + JSON.stringify( {
            id: req.user.id,
            timeCreated: Date.now()
        } );

        // Convert to base64 string
        const base64TokenString = await this.asciiToBase64( tokenString );

        // Create signature string base 64
        const signatureString = await this.signToken( tokenString );

        // Add both strings using '.' as separator
        const combinedTokenString = base64TokenString + '.' + signatureString;

        // Make url safe and add to req.user.token
        req.user.token = await this.makeStringUrlSafe( combinedTokenString );
        next();
    }

    /**
     * Read base64 signed user token
     * @param req
     * @param res
     * @param next
     */
    async decryptVerifyWebTokenSignedBase64( req, res, next ) {
        // Reverse make url safe
        const combinedTokenString = await this.reverseStringUrlSafe( req.user.token );

        // Split string to token and signature string
        const splitTokenString = combinedTokenString.split( '.' );
        const tokenString = splitTokenString[ 0 ];
        const signatureString = splitTokenString[ 1 ];
        const decryptedTokenString = await this.base64ToAscii( tokenString );

        // Verify signature
        if ( this.verifySignature( decryptedTokenString, signatureString ) ) {
            console.log( 'Signature verified' );
            console.log( decryptedTokenString );
            // If signature verified decrypt string
            req.user.token = await JSON.parse( decryptedTokenString );
            // req.user._id = req.user.token.payload._id;
        } else {
            // Signature not verified give error message
            console.log( 'Signature not verified' );
        }
        next();
    }

    /**
     * Create password reset token and attach to req
     * @param req
     * @param res
     * @param next
     */
    async createPasswordResetTokenSignedEncrypted( req, res, next ) {
        req.user.token = await this.createJWT( { type: "reset" },
            {
                id: req.user.id,
                timeCreated: Date.now()
            } );
        next();
    }

    /**
     * Read base64 signed user token
     * @param req
     * @param res
     * @param next
     */
    async readPasswordResetTokenSignedEncrypted( req, res, next ) {
        next();
    }

    /**
     * Creates the token object ready for encryption
     * this object will be replaced by token string
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    createTokenObjectForEncryption( req ) {
    }
}


module.exports = AuthPc;
