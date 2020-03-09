const JwtMiddleware = require( 'jwt_pc' );


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
     * Create user token and attach to req
     * @param req
     * @param res
     * @param next
     */
    createToken( req, res, next ) {

    }

    /**
     * Create password reset token and attach to req
     * @param req
     * @param res
     * @param next
     */
    async createPasswordResetToken( req, res, next ) {
        req.user.token = await this.createJWT( { type: "pw_reset" },
            {
                _id: req.user._id,
                time_created: Date.now()
            } );
        next();
    }

}


module.exports = AuthPc;
