const JwtMiddleware = require( './JwtMiddleware' );

/**
 * This class works on req.user object if this is as below
 * req object should looks as follows
 * some attributes may be missing
 * {
 *     req: {
 *         user: {
 *             username: "some username",
 *             password: "some password",
 *             id: "some id string",
 *             type: "some user type",
 *             salt: "some salt string",
 *             hash: "password and salt hash string",
 *             .
 *             .
 *             .
 *             storedUser: "user stored in database",
 *             token: {
 *                 header: "some token header",
 *                 payload: "some token payload"
 *             },
 *             webToken: "some web token string including signature string",
 *             webTokenSignature: "some signature string"
 *         }
 *     }
 * }
 *
 * req.user.token -> contain token object
 * req.user.webToken -> contain web token to be sent to received from user
 */
class Auth extends JwtMiddleware {
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
     * Create encrypted and signed user token and attach to req.user.webToken
     * req should contain
     * @param req
     * @param res
     * @param next
     */
    async createWebTokenSignedEncrypted( req, res, next ) {
        req.user.webToken = await this.createJWT( { type: "web" },
            {
                id: req.user.id,
                timeCreated: Date.now()
            } );
        next();
    }

    /**
     * Decrypt signed web token
     * @param req
     * @param res
     * @param next
     */
    async decryptWebTokenSignedEncrypted( req, res, next ) {
        const token = await this.readJWT( req.user.webToken );

        if ( token.payload.id !== 'undefined' ) {
            req.user.id = token.payload.id;
        } else {
            req.user.id = null
        }

        req.user = { ...req.user, token: token };
        next();
    }

    /**
     * Create base64 signed user token and attach to req.user.webToken
     * req should contain
     * @param req
     * @param res
     * @param next
     */
    async createWebTokenSignedBase64( req, res, next ) {

        // Create token object
        req.user.token = {
            header: { type: "web" },
            payload: {
                id: req.user.id,
                timeCreated: Date.now()
            }
        };

        // Create signature string base 64
        req.user.webTokenSignature = await this.signToken( JSON.stringify( req.user.token ) );

        // Add both strings using '.' as separator
        const combinedTokenString = await this.asciiToBase64( JSON.stringify( req.user.token ) ) +
            '.' + req.user.webTokenSignature;

        // Make url safe and add to req.user.token
        req.user.webToken = await this.makeStringUrlSafe( combinedTokenString );
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
        const combinedTokenString = await this.reverseStringUrlSafe( req.user.webToken );

        // Split string to token and signature string
        const splitTokenString = combinedTokenString.split( '.' );

        const tokenString = splitTokenString[ 0 ];
        req.user.webTokenSignature = splitTokenString[ 1 ];
        const decryptedTokenString = await this.base64ToAscii( tokenString );

        // Verify signature
        if ( this.verifySignature( decryptedTokenString, req.user.webTokenSignature ) ) {
            // Signature verified
            req.user.token = await JSON.parse( decryptedTokenString );
            req.user.id = req.user.token.payload.id;
        } else {
            // Signature not verified
            req.user.id = null;
            req.user.token = null;
        }

        next();
    }

    /**
     * Compare hash for login
     * User has been found by username and attached to req.user.storedUser
     * req.user.storedUser.hash contain stored hash of password
     * req.user.salt contain stored salt, it must be put here in advance from database
     * if hash comparison is true storedUser is merged in req.user and storedUser set to null
     * else req.user.id is set to null rest of the information is removed from req.user
     */
    async comparePasswordHash( req, res, next ) {

    }
}


module.exports = Auth;
