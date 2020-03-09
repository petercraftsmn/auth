const express = require( 'express' );
const router = express.Router();
const users = require( './users' );


module.exports = ( params ) => {

    const parameters = params;

    /** GET home page. */
    router.get( '/', function ( req, res, next ) {
        res.send( { message: 'This is landing from here' } );
    } );

    router.use( '/user', users );

    return router;
};


