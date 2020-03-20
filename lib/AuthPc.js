const JwtMiddleware = require( './JwtMiddleware' );


class AuthPc extends JwtMiddleware {
    constructor( keys ) {
        super( keys );
    }

    /**
     * Create salt for any purpose
     * @param req
     * @param res
     * @param next
     */
    async createSalt( req, res, next ) {
        req.user.salt = await this.saltCreator();
        next();
    }

    /**
     * Create hash of password and attach to request
     * @param req
     * @param res
     * @param next
     */
    async createPasswordHash( req, res, next ) {
        req.user.hash = await this.hashCreator( req.user.password + req.user.salt );
        next();
    }

    /**
     * Create salt and password hash and attache to req
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
     * Create user token and attach to req.user.token
     * req should contain
     * @param req
     * @param res
     * @param next
     */
    async createWebToken( req, res, next ) {
        req.user.token = await this.createJWT( { type: "web" },
            {
                _id: req.user._id,
                time_created: Date.now()
            } );
        next();
    }

    /**
     * Create password reset token and attach to req
     * @param req
     * @param res
     * @param next
     */
    async createPasswordResetToken( req, res, next ) {
        req.user.token = await this.createJWT( { type: "reset" },
            {
                _id: req.user._id,
                time_created: Date.now()
            } );
        next();
    }

    /**
     * Decrypts token using key
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async decryptToken( req, res, next ) {
        next();
    }

    /**
     * Verifies signature of token
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async verifyTokenSignature( req, res, next ) {
        next();
    }

    /**
     * Converts token into json and attaches to user
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async readToken( req, res, next ) {
        next();
    }

}


module.exports = AuthPc;
