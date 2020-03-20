const Jwt = require( '@petercraftsmn/crypt' );


class JwtMiddleware extends Jwt {
    constructor( keys ) {
        super( keys );
    }

    /**
     * Reads the jwt from req
     * Parses and attaches the parsed_token.header and parsed_token.payload to req
     * @param req
     * @param res
     * @param next
     */
    async bodyJwtToUser( req, res, next ) {

        if ( req.body === undefined || req.body === null ) {
            req.parsed_token = null;
            req.user = { message: "no token present", _id: null, exist: false };
            next();
        } else {
            if ( req.body.token !== undefined || typeof req.body.token === "string" ) {
                req.parsed_token = await this.readJWT( req.body.token );
                this.attachUserToReq( req, res, next );
            } else {
                req.parsed_token = null;
                req.user = { message: "no token present", _id: null, exist: false };
                next();
            }
        }
    };

    /**
     * Parses jwt token from Authorization header
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async headerJwtToUser( req, res, next ) {

        if ( req.get( 'Authorization' ) === undefined || req.get( 'Authorization' ) === null ) {
            req.parsed_token = null;
            req.user = { message: "no token present", _id: null, exist: false };
            next();
        } else {
            req.parsed_token = await this.readJWT( req.get( 'Authorization' ) );
            this.attachUserToReq( req, res, next );
        }

    };

    /**
     * Attaches user to request
     * @param req
     * @param res
     * @param next
     */
    attachUserToReq( req, res, next ) {
        if ( req.parsed_token.header === false ) {
            req.user = { message: "no token present", _id: null, exist: false };
            next();
        } else {
            req.parsed_token.header = JSON.parse( req.parsed_token.header );
            req.parsed_token.payload = JSON.parse( req.parsed_token.payload );
            req.user = {
                message: null,
                _id: req.parsed_token.payload._id,
                type: req.parsed_token.payload.type,
                exist: true
            };
            next();
        }
    }
}

module.exports = JwtMiddleware;

