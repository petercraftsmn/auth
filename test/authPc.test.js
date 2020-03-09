const assert = require( 'assert' ).strict;
const keys = require( './keys/keys' );
const AuthPc = require( '../lib/AuthPc' );


describe( 'AuthPc middleware test', function () {
    const authPc = new AuthPc( keys );
    let req = {
        user: {
            username: "peter@example.com",
            password: "my-secret-password",
            _id: "kkjwhhwllwhwl3l3hh4lljssl"
        }
    };
    let res = {};
    let nextFunc = function ( req, res ) {
    };

    afterEach( () => {
        req = {
            user: {
                username: "peter@example.com",
                password: "my-secret-password",
                _id: "kkjwhhwllwhwl3l3hh4lljssl"
            }
        };
    } );

    describe( 'create salt, hash and tokens', function () {
        it( 'createSalt and attach to req', function ( done ) {
            authPc.createSalt( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.salt, 'Salt is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createPasswordHash and attach to req', function ( done ) {
            authPc.createPasswordHash( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.hash, 'Hash is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createSaltAndPasswordHash and attach to req', function ( done ) {
            authPc.createSaltAndPasswordHash( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.salt, 'Salt is absent' );
                    assert.ok( req.user.hash, 'Hash is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createPasswordResetToken and attach to req', function ( done ) {
            authPc.createPasswordResetToken( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.token, 'Token is absent' );
                    done();
                } )
                .catch( done );
        } );
    } );

} );

