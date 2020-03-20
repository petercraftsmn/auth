const JwtMiddleware = require( './JwtMiddleware' );


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
                _id: req.user._id,
                time_created: Date.now()
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

        if ( token.payload._id !== 'undefined' ) {
            req.user._id = token.payload._id;
        } else {
            req.user._id = null
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
    async createWebTokenBase64( req, res, next ) {
        next();
    }

    /**
     * Read base64 signed user token
     * @param req
     * @param res
     * @param next
     */
    async readWebTokenBase64( req, res, next ) {
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
                _id: req.user._id,
                time_created: Date.now()
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


}


module.exports = AuthPc;
